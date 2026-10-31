// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// search.go – WebDAV SEARCH handler (RFC 5323).
// Supports the full basicsearch grammar: logical (and/or/not), ordered
// comparisons (eq/lt/gt/lte/gte), and string matches (like/contains).
// <d:select><d:prop> is honoured; unknown properties are returned in a
// separate 404 propstat block per RFC 4918 §9.1. <d:orderby> (§5.6) and
// <d:limit><d:nresults> (§5.17) are honoured; results are always sorted so
// that truncated result sets are deterministic (§2.3.1).

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---- Request XML structures -------------------------------------------------

type searchRequest struct {
	BasicSearch searchBasic `xml:"basicsearch"`
}

type searchBasic struct {
	Select searchSelect `xml:"select"`
	From   searchFrom   `xml:"from"`
	Where  struct {
		InnerXML []byte `xml:",innerxml"`
	} `xml:"where"`
	OrderBy struct {
		Orders []searchOrder `xml:"order"`
	} `xml:"orderby"`
	Limit *searchLimit `xml:"limit"`
}

// searchOrder is one <d:order> of RFC 5323 §5.6.
type searchOrder struct {
	Prop struct {
		Props []anyElem `xml:",any"`
	} `xml:"prop"`
	Ascending  *struct{} `xml:"ascending"`
	Descending *struct{} `xml:"descending"`
}

// searchLimit is <d:limit> of RFC 5323 §5.17.
type searchLimit struct {
	NResults *string `xml:"nresults"`
}

type searchSelect struct {
	Prop struct {
		Props []anyElem `xml:",any"`
	} `xml:"prop"`
}

type anyElem struct {
	XMLName xml.Name
}

type searchFrom struct {
	Scope searchScope `xml:"scope"`
}

type searchScope struct {
	Href  string `xml:"href"`
	Depth string `xml:"depth"`
}

// ---- AST types --------------------------------------------------------------

// WhereNode is a node in the SEARCH where-clause AST (RFC 5323 §5.14).
type WhereNode interface{ isWhereNode() }

type andNode struct{ children []WhereNode }
type orNode struct{ children []WhereNode }
type notNode struct{ child WhereNode }
type compNode struct {
	op      string // eq|lt|gt|lte|gte|like|contains
	prop    string // property local name
	literal string
}

func (andNode) isWhereNode()  {}
func (orNode) isWhereNode()   {}
func (notNode) isWhereNode()  {}
func (compNode) isWhereNode() {}

// ---- AST parser -------------------------------------------------------------

// parseWhereAST parses the raw inner XML of <d:where> into a WhereNode tree.
// Returns nil when the where element is empty (match everything).
func parseWhereAST(innerXML []byte) (WhereNode, error) {
	inner := bytes.TrimSpace(innerXML)
	if len(inner) == 0 {
		return nil, nil
	}
	// Re-wrap with namespace context so the decoder can resolve d: prefixes.
	wrapped := append([]byte(`<w xmlns:d="DAV:" xmlns="DAV:">`), inner...)
	wrapped = append(wrapped, []byte(`</w>`)...)
	dec := xml.NewDecoder(bytes.NewReader(wrapped))
	dec.Token() // consume <w>
	return parseNode(dec)
}

func parseNode(dec *xml.Decoder) (WhereNode, error) {
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		return dispatchNode(dec, se)
	}
}

func dispatchNode(dec *xml.Decoder, se xml.StartElement) (WhereNode, error) {
	switch se.Name.Local {
	case "and":
		return parseLogical(dec, se, "and")
	case "or":
		return parseLogical(dec, se, "or")
	case "not":
		return parseNot(dec, se)
	case "eq", "lt", "gt", "lte", "gte", "like", "contains":
		return parseComp(dec, se, se.Name.Local)
	default:
		return nil, fmt.Errorf("unknown where-clause element <%s>", se.Name.Local)
	}
}

func parseLogical(dec *xml.Decoder, se xml.StartElement, op string) (WhereNode, error) {
	var children []WhereNode
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child, err := dispatchNode(dec, t)
			if err != nil {
				return nil, err
			}
			children = append(children, child)
		case xml.EndElement:
			if t.Name.Local == se.Name.Local {
				if op == "and" {
					return andNode{children}, nil
				}
				return orNode{children}, nil
			}
		}
	}
}

func parseNot(dec *xml.Decoder, se xml.StartElement) (WhereNode, error) {
	child, err := parseNode(dec)
	if err != nil {
		return nil, err
	}
	// Consume the closing </not>.
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if ee, ok := tok.(xml.EndElement); ok && ee.Name.Local == "not" {
			break
		}
	}
	return notNode{child}, nil
}

func parseComp(dec *xml.Decoder, se xml.StartElement, op string) (WhereNode, error) {
	var propName, literal string
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "prop":
				propName, err = parsePropName(dec)
				if err != nil {
					return nil, err
				}
			case "literal":
				literal, err = parseText(dec, "literal")
				if err != nil {
					return nil, err
				}
			default:
				if err := dec.Skip(); err != nil {
					return nil, err
				}
			}
		case xml.EndElement:
			if t.Name.Local == se.Name.Local {
				return compNode{op: op, prop: propName, literal: literal}, nil
			}
		}
	}
}

// parsePropName reads the first child element name inside <d:prop>.
func parsePropName(dec *xml.Decoder) (string, error) {
	name := ""
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name = t.Name.Local
			dec.Skip()
		case xml.EndElement:
			if t.Name.Local == "prop" {
				return name, nil
			}
		}
	}
}

// parseText reads character data until the matching close tag.
func parseText(dec *xml.Decoder, closeName string) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			if t.Name.Local == closeName {
				return sb.String(), nil
			}
		}
	}
}

// ---- AST evaluator ----------------------------------------------------------

// searchTypeError signals a type mismatch (ordered comparison on a string prop).
type searchTypeError struct{ prop, literal string }

func (e *searchTypeError) Error() string {
	return fmt.Sprintf("ordered comparison not valid for string property %q (literal: %q)", e.prop, e.literal)
}

// propCategory returns the comparison type for a property name.
func propCategory(name string) string {
	switch name {
	case "getlastmodified":
		return "date-rfc1123"
	case "creationdate":
		return "date-iso8601"
	case "getcontentlength":
		return "integer"
	default:
		return "string"
	}
}

// evalPropStr returns the string representation of a property for comparison.
func evalPropStr(fp FileProps, name string) string {
	switch name {
	case "getlastmodified":
		return fp.LastModified
	case "creationdate":
		return fp.CreationDate
	case "getcontentlength":
		return strconv.FormatInt(fp.ContentLength, 10)
	case "getcontenttype":
		return fp.ContentType
	case "displayname":
		return fp.DisplayName
	}
	return ""
}

func evalWhere(node WhereNode, fp FileProps) (bool, error) {
	if node == nil {
		return true, nil
	}
	switch n := node.(type) {
	case andNode:
		for _, c := range n.children {
			ok, err := evalWhere(c, fp)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	case orNode:
		for _, c := range n.children {
			ok, err := evalWhere(c, fp)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case notNode:
		ok, err := evalWhere(n.child, fp)
		return !ok, err
	case compNode:
		return evalComp(n, fp)
	}
	return false, fmt.Errorf("unknown AST node type")
}

func evalComp(n compNode, fp FileProps) (bool, error) {
	cat := propCategory(n.prop)

	// like and contains require a string property.
	if (n.op == "like" || n.op == "contains") && cat != "string" {
		return false, fmt.Errorf("operator %q requires a string property, not %q", n.op, n.prop)
	}
	// Ordered comparisons are not defined for string properties.
	if cat == "string" && (n.op == "lt" || n.op == "gt" || n.op == "lte" || n.op == "gte") {
		return false, &searchTypeError{n.prop, n.literal}
	}

	switch cat {
	case "date-rfc1123":
		return evalDateComp(n, fp, http.TimeFormat)
	case "date-iso8601":
		return evalDateComp(n, fp, time.RFC3339)
	case "integer":
		return evalIntComp(n, fp)
	case "string":
		return evalStringComp(n, fp)
	}
	return false, nil
}

// evalDateComp compares at whole-second granularity because the literal is
// an HTTP-date (or a second-precision ISO date); comparing nanosecond mtimes
// against it would make "eq" never match and shift "gt" by up to a second.
// Both getlastmodified and creationdate are derived from the mtime.
func evalDateComp(n compNode, fp FileProps, layout string) (bool, error) {
	var lit time.Time
	var err error
	// RFC1123Z covers `date -uR` on macOS; RFC1123 also accepts "UTC".
	for _, l := range []string{layout, time.RFC1123, time.RFC1123Z, time.RFC3339} {
		if lit, err = time.Parse(l, n.literal); err == nil {
			break
		}
	}
	if err != nil {
		return false, fmt.Errorf("unparseable date literal %q: %w", n.literal, err)
	}
	t := fp.ModTime.Truncate(time.Second)
	return compareOrder(n.op, t.Compare(lit.Truncate(time.Second)))
}

func evalIntComp(n compNode, fp FileProps) (bool, error) {
	v := fp.ContentLength
	lit, err := strconv.ParseInt(n.literal, 10, 64)
	if err != nil {
		return false, fmt.Errorf("non-integer literal %q for numeric property %q", n.literal, n.prop)
	}
	cmp := 0
	if v < lit {
		cmp = -1
	} else if v > lit {
		cmp = 1
	}
	return compareOrder(n.op, cmp)
}

func evalStringComp(n compNode, fp FileProps) (bool, error) {
	val := strings.ToLower(evalPropStr(fp, n.prop))
	lit := strings.ToLower(n.literal)
	switch n.op {
	case "eq":
		return val == lit, nil
	case "like":
		return likeMatch(lit, val)
	case "contains":
		return strings.Contains(val, lit), nil
	}
	return false, nil
}

// compareOrder maps a comparison operator to a result given a cmp value
// (-1, 0, +1) from time.Compare or a manual integer comparison.
func compareOrder(op string, cmp int) (bool, error) {
	switch op {
	case "eq":
		return cmp == 0, nil
	case "lt":
		return cmp < 0, nil
	case "gt":
		return cmp > 0, nil
	case "lte":
		return cmp <= 0, nil
	case "gte":
		return cmp >= 0, nil
	}
	return false, nil
}

// likeMatch implements SQL-style LIKE matching where % is a wildcard.
func likeMatch(pattern, value string) (bool, error) {
	// Convert %-wildcards to regexp .*; escape everything else.
	parts := strings.Split(pattern, "%")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$")
	if err != nil {
		return false, err
	}
	return re.MatchString(value), nil
}

// ---- orderby / limit (RFC 5323 §5.6, §5.17) -------------------------------

// sortKey is one parsed <d:order>.
type sortKey struct {
	prop       string
	descending bool
}

// sortableProps lists the properties <d:orderby> accepts.
var sortableProps = map[string]bool{
	"getlastmodified":  true,
	"creationdate":     true,
	"getcontentlength": true,
	"displayname":      true,
	"getcontenttype":   true,
	"getetag":          true,
}

func parseOrderBy(orders []searchOrder) ([]sortKey, error) {
	var keys []sortKey
	for _, o := range orders {
		if len(o.Prop.Props) != 1 {
			return nil, fmt.Errorf("each <order> needs exactly one property, got %d", len(o.Prop.Props))
		}
		name := o.Prop.Props[0].XMLName.Local
		if !sortableProps[name] {
			return nil, fmt.Errorf("unsupported orderby property %q", name)
		}
		if o.Ascending != nil && o.Descending != nil {
			return nil, fmt.Errorf("order on %q is both ascending and descending", name)
		}
		keys = append(keys, sortKey{prop: name, descending: o.Descending != nil})
	}
	return keys, nil
}

// parseNResults returns 0 when no limit was requested.
func parseNResults(l *searchLimit) (int, error) {
	if l == nil {
		return 0, nil
	}
	if l.NResults == nil {
		return 0, fmt.Errorf("<limit> without <nresults>")
	}
	n, err := strconv.Atoi(strings.TrimSpace(*l.NResults))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("nresults must be a positive integer, got %q", *l.NResults)
	}
	return n, nil
}

// asciiFold implements the i;ascii-casemap collation used for string sorting:
// only A–Z are folded so the order does not depend on Unicode case rules.
func asciiFold(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// compareProp orders two entries by one property. A missing value is lower
// than any present value (RFC 5323 §5.6), so it comes first when ascending.
func compareProp(a, b FileProps, prop string) int {
	switch prop {
	case "getlastmodified", "creationdate":
		return a.ModTime.Compare(b.ModTime)
	case "getcontentlength":
		switch {
		case a.IsDir && b.IsDir:
			return 0
		case a.IsDir:
			return -1
		case b.IsDir:
			return 1
		}
		return cmpInt64(a.ContentLength, b.ContentLength)
	}
	av, aok := getPropValue(a, prop)
	bv, bok := getPropValue(b, prop)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	return strings.Compare(asciiFold(av), asciiFold(bv))
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// sortResults applies the orderby keys, earlier keys being more significant,
// and falls back to href so equal keys never produce a random order.
func sortResults(results []FileProps, keys []sortKey) {
	slices.SortFunc(results, func(a, b FileProps) int {
		for _, k := range keys {
			c := compareProp(a, b, k.prop)
			if k.descending {
				c = -c
			}
			if c != 0 {
				return c
			}
		}
		return strings.Compare(a.Href, b.Href)
	})
}

// ---- Handler ----------------------------------------------------------------

// resolveScope parses the scope href as a URI reference (RFC 5323 §5.4,
// RFC 3986 §4.1) and returns its decoded path relative to the arbiter's root.
// Query and fragment are not part of the scope and are dropped. inside is
// false when the scope lies outside this arbiter's namespace: an absolute URI
// with another scheme or host, or one that leaves the share (§2.2.2).
// Hrefs at a share carry the share prefix, so a path under it is taken
// relative to the arbiter /s/<id>/; any other path stays relative to the
// share root, the Nextcloud convention clients such as LogWizard rely on.
func resolveScope(r *http.Request, href, urlPrefix string) (scope string, inside bool, err error) {
	// RFC 3986 Appendix C: whitespace around a URI in a document is not
	// part of it; pretty-printed XML puts it there.
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return "", false, fmt.Errorf("parse scope %q: %w", href, err)
	}
	hasPrefix := urlPrefix != "" && (u.Path == urlPrefix || strings.HasPrefix(u.Path, urlPrefix+"/"))
	if u.Scheme != "" || u.Host != "" {
		// An absolute URI names exactly one resource, so the compat form
		// relative to the share root does not apply to it.
		if !scopeOnServer(u, r) || (urlPrefix != "" && !hasPrefix) {
			return "", false, nil
		}
	}
	if hasPrefix {
		return strings.TrimPrefix(u.Path, urlPrefix), true, nil
	}
	return u.Path, true, nil
}

// scopeOnServer reports whether an absolute scope URI names this server as the
// request reached it. Default ports are equivalent to none (RFC 3986 §6.2.3).
func scopeOnServer(u *url.URL, r *http.Request) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if u.Scheme != "" && !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	defaultPort := map[string]string{"http": ":80", "https": ":443"}[scheme]
	return strings.EqualFold(strings.TrimSuffix(u.Host, defaultPort), strings.TrimSuffix(r.Host, defaultPort))
}

// writeScopeInvalid answers a scope that does not exist or lies outside the
// namespace: 409 with the search-scope-valid precondition naming the scope
// with a 404 response (RFC 5323 §2.2.2, example in §2.4.1).
func writeScopeInvalid(w http.ResponseWriter, href string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><d:error xmlns:d="DAV:"><d:search-scope-valid><d:response><d:href>%s</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response></d:search-scope-valid></d:error>`,
		xmlEsc(strings.TrimSpace(href)))
}

// handleSearch handles WebDAV SEARCH requests (RFC 5323).
// urlPrefix is prepended to every href in the multistatus response; pass ""
// for the normal user endpoint and "/s/{share_id}" for the share endpoint.
// owner is the user whose stored DAV:displayname values apply.
func handleSearch(w http.ResponseWriter, r *http.Request, dataDir string, urlPrefix, owner string) {
	// Clients use Date minus one second as the watermark for their next
	// getlastmodified query. Go would stamp Date only when the headers are
	// written, i.e. after the walk, so changes made during a long walk would
	// fall behind the watermark. Pin it to the moment before the walk.
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isBodyTooLarge(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}

	var req searchRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("malformed XML: %v", err), http.StatusBadRequest)
		return
	}

	// Resolve selected property names.
	var selected []string
	for _, p := range req.BasicSearch.Select.Prop.Props {
		selected = append(selected, p.XMLName.Local)
	}
	if len(selected) == 0 {
		selected = allPropNames // no select → return all
	}
	known, unknown := splitRequested(selected)

	// Parse the where-clause AST.
	whereAST, err := parseWhereAST(req.BasicSearch.Where.InnerXML)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid where-clause: %v", err), http.StatusBadRequest)
		return
	}

	sortKeys, err := parseOrderBy(req.BasicSearch.OrderBy.Orders)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid orderby: %v", err), http.StatusBadRequest)
		return
	}
	nresults, err := parseNResults(req.BasicSearch.Limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid limit: %v", err), http.StatusBadRequest)
		return
	}

	scopeHref := req.BasicSearch.From.Scope.Href
	scope, inside, err := resolveScope(r, scopeHref, urlPrefix)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid scope: %v", err), http.StatusBadRequest)
		return
	}
	depth := req.BasicSearch.From.Scope.Depth
	if depth == "" {
		depth = "infinity"
	}

	logger.Debug("SEARCH parsed",
		"scope", scope, "depth", depth,
		"props", selected, "where", fmt.Sprintf("%T", whereAST),
		"orderby", sortKeys, "nresults", nresults,
	)

	if !inside {
		writeScopeInvalid(w, scopeHref)
		return
	}

	// Walk the directory tree and evaluate the where AST for each file.
	cleanScope := strings.TrimPrefix(filepath.Clean("/"+scope), "/")
	root := filepath.Join(dataDir, cleanScope)

	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			writeScopeInvalid(w, scopeHref)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	if !info.IsDir() {
		http.Error(w, "scope is not a directory", http.StatusBadRequest)
		return
	}

	// RFC 5323 §5.3 and §5.17 work on property values, so a stored displayname
	// must be in place before the where clause and the sort see the entry.
	locks := userLocks(owner)
	displayNames, err := loadDisplayNames(owner, locks.nameOf(root))
	if err != nil {
		serviceUnavailable(w, r, "dead property lookup failed", err)
		return
	}

	var matches []FileProps
	var walkErr error

	filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if depth == "1" && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(fi.Name(), tmpPrefix) {
			return nil
		}
		fp := buildFileProps(dataDir, path, fi)
		if p, ok := displayNames[locks.nameOf(path)]; ok {
			fp.setDisplayName(p)
		}
		if urlPrefix != "" {
			fp.Href = urlPrefix + fp.Href
		}
		match, evalErr := evalWhere(whereAST, fp)
		if evalErr != nil {
			walkErr = evalErr
			return filepath.SkipAll
		}
		if match {
			matches = append(matches, fp)
		}
		return nil
	})

	if walkErr != nil {
		if _, isType := walkErr.(*searchTypeError); isType {
			http.Error(w, walkErr.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "evaluation error: "+walkErr.Error(), http.StatusBadRequest)
		}
		return
	}

	// Truncation must keep the entries that sort first (§5.17.1), so sort
	// before cutting.
	sortResults(matches, sortKeys)
	if nresults > 0 && len(matches) > nresults {
		matches = matches[:nresults]
	}
	var responses strings.Builder
	for _, fp := range matches {
		writeFileResponse(&responses, fp, known, unknown)
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">%s</d:multistatus>`,
		responses.String())
}
