// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

// decodeHrefText reverses hrefXML. Going through encoding/xml rather than a
// string replace also proves the output is well-formed XML character data.
func decodeHrefText(t *testing.T, text string) string {
	t.Helper()
	var v struct {
		Href string `xml:",chardata"`
	}
	if err := xml.Unmarshal([]byte("<href>"+text+"</href>"), &v); err != nil {
		t.Fatalf("href %q is not valid XML text: %v", text, err)
	}
	p, err := url.PathUnescape(v.Href)
	if err != nil {
		t.Fatalf("href %q does not percent-decode: %v", v.Href, err)
	}
	return p
}

// TestHrefXML pins the RFC 4918 §8.3 href encoding. The decoded result must be
// byte-identical to the input because clients reuse the href as request path.
func TestHrefXML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"root", "/", "/"},
		{"plain", "/docs/readme.txt", "/docs/readme.txt"},
		{"collection trailing slash", "/docs/sub/", "/docs/sub/"},
		{"space", "/my file.txt", "/my%20file.txt"},
		{"sharp s", "/stra\xc3\x9fe", "/stra%C3%9Fe"},
		{"NFC u umlaut", "/\xc3\xbc.txt", "/%C3%BC.txt"},
		// NFD must stay NFD: normalizing would yield an href that no longer
		// names the file stored on disk.
		{"NFD u umlaut", "/u\xcc\x88.txt", "/u%CC%88.txt"},
		{"german quotes", "/\xe2\x80\x9eq\xe2\x80\x9c", "/%E2%80%9Eq%E2%80%9C"},
		{"percent", "/100%.txt", "/100%25.txt"},
		{"hash", "/a#b", "/a%23b"},
		{"question mark", "/a?b", "/a%3Fb"},
		// "+" and "&" are legal path characters, so EscapedPath keeps them;
		// "&" then needs XML escaping to remain valid character data.
		{"plus", "/a+b", "/a+b"},
		{"ampersand", "/a&b/", "/a&amp;b/"},
		{"angle brackets", "/<x>", "/%3Cx%3E"},
		{"nested non-ASCII collection", "/\xc3\xa4/b c/", "/%C3%A4/b%20c/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hrefXML(tt.in)
			if got != tt.want {
				t.Errorf("hrefXML(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if back := decodeHrefText(t, got); back != tt.in {
				t.Errorf("round trip of %q gave %q", tt.in, back)
			}
		})
	}
}

// TestHrefXMLNoNormalization guards against a future change that would make
// NFC and NFD names collide in a multistatus response.
func TestHrefXMLNoNormalization(t *testing.T) {
	if nfc, nfd := hrefXML("/\xc3\xbc"), hrefXML("/u\xcc\x88"); nfc == nfd {
		t.Errorf("NFC and NFD encode identically: %q", nfc)
	}
}

// TestResolveScope covers the scope href rules of RFC 5323 §5.4 and the
// out-of-namespace detection that triggers search-scope-valid (§2.2.2).
func TestResolveScope(t *testing.T) {
	tests := []struct {
		name       string
		target     string // request URL; its host becomes r.Host
		href       string
		prefix     string
		wantScope  string
		wantInside bool
		wantErr    bool
	}{
		{name: "absolute path", target: "http://example.com/", href: "/docs/", wantScope: "/docs/", wantInside: true},
		{name: "relative path", target: "http://example.com/", href: "docs/a", wantScope: "docs/a", wantInside: true},
		{name: "root", target: "http://example.com/", href: "/", wantScope: "/", wantInside: true},
		{name: "percent-decoded", target: "http://example.com/", href: "/a%20b/%C3%BC", wantScope: "/a b/\xc3\xbc", wantInside: true},
		{name: "whitespace trimmed", target: "http://example.com/", href: "\n  /docs/\t ", wantScope: "/docs/", wantInside: true},
		{name: "query and fragment dropped", target: "http://example.com/", href: "/docs?x=1#frag", wantScope: "/docs", wantInside: true},
		{name: "invalid escape bare", target: "http://example.com/", href: "%#", wantErr: true},
		{name: "invalid escape in path", target: "http://example.com/", href: "/a%zz", wantErr: true},
		{name: "same host absolute", target: "http://example.com/", href: "http://example.com/docs", wantScope: "/docs", wantInside: true},
		{name: "same host explicit default port", target: "http://example.com/", href: "http://example.com:80/docs", wantScope: "/docs", wantInside: true},
		{name: "request with default port", target: "http://example.com:80/", href: "http://example.com/docs", wantScope: "/docs", wantInside: true},
		{name: "same host non-default port", target: "http://example.com:8080/", href: "http://example.com:8080/docs", wantScope: "/docs", wantInside: true},
		{name: "port mismatch", target: "http://example.com:8080/", href: "http://example.com/docs", wantInside: false},
		{name: "host case-insensitive", target: "http://example.com/", href: "HTTP://EXAMPLE.COM/docs", wantScope: "/docs", wantInside: true},
		{name: "network-path reference same host", target: "http://example.com/", href: "//example.com/docs", wantScope: "/docs", wantInside: true},
		{name: "other host", target: "http://example.com/", href: "http://other.example/docs", wantInside: false},
		{name: "network-path reference other host", target: "http://example.com/", href: "//other.example/docs", wantInside: false},
		{name: "other scheme", target: "http://example.com/", href: "https://example.com/docs", wantInside: false},
		{name: "non-http scheme", target: "http://example.com/", href: "ftp://example.com/docs", wantInside: false},
		{name: "https same host", target: "https://example.com/", href: "https://example.com/docs", wantScope: "/docs", wantInside: true},
		{name: "https default port", target: "https://example.com/", href: "https://example.com:443/docs", wantScope: "/docs", wantInside: true},
		{name: "http on https request", target: "https://example.com/", href: "http://example.com/docs", wantInside: false},

		{name: "share path under prefix", target: "http://example.com/", prefix: "/s/abc", href: "/s/abc/docs/", wantScope: "/docs/", wantInside: true},
		// The empty scope is the share root; handleSearch cleans it to "/".
		{name: "share prefix itself", target: "http://example.com/", prefix: "/s/abc", href: "/s/abc", wantScope: "", wantInside: true},
		{name: "share prefix encoded child", target: "http://example.com/", prefix: "/s/abc", href: "/s/abc/a%20b", wantScope: "/a b", wantInside: true},
		{name: "share root-relative compat", target: "http://example.com/", prefix: "/s/abc", href: "/docs/", wantScope: "/docs/", wantInside: true},
		{name: "share longer id not a prefix", target: "http://example.com/", prefix: "/s/abc", href: "/s/abcdef/x", wantScope: "/s/abcdef/x", wantInside: true},
		{name: "share absolute under prefix", target: "http://example.com/", prefix: "/s/abc", href: "http://example.com/s/abc/docs", wantScope: "/docs", wantInside: true},
		{name: "share absolute outside prefix", target: "http://example.com/", prefix: "/s/abc", href: "http://example.com/docs", wantInside: false},
		{name: "share absolute other share", target: "http://example.com/", prefix: "/s/abc", href: "http://example.com/s/xyz/docs", wantInside: false},
		{name: "share absolute other host", target: "http://example.com/", prefix: "/s/abc", href: "http://other.example/s/abc/docs", wantInside: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("SEARCH", tt.target, nil)
			scope, inside, err := resolveScope(r, tt.href, tt.prefix)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveScope(%q) = %q, %v; want error", tt.href, scope, inside)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveScope(%q): unexpected error %v", tt.href, err)
			}
			if inside != tt.wantInside {
				t.Fatalf("resolveScope(%q) inside = %v, want %v", tt.href, inside, tt.wantInside)
			}
			// The scope string is meaningless once the href is outside.
			if inside && scope != tt.wantScope {
				t.Errorf("resolveScope(%q) scope = %q, want %q", tt.href, scope, tt.wantScope)
			}
		})
	}
}

// TestLikeMatch checks the "%" wildcard of RFC 5323 §5.15.1, that regexp
// metacharacters in the pattern stay literal, and that the match is anchored
// to the whole value. The "_" wildcard and "\" escape are not covered because
// likeMatch does not implement them yet.
func TestLikeMatch(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"report", "report", true},
		{"report", "report.pdf", false},
		{"report", "my report", false},
		{"%.pdf", "report.pdf", true},
		{"%.pdf", "report.pdf.bak", false},
		{"rep%", "report.pdf", true},
		{"%port%", "report.pdf", true},
		{"%", "", true},
		{"%", "anything", true},
		{"a%b%c", "aXXbYYc", true},
		{"a%b%c", "acb", false},
		{"a.b", "a.b", true},
		{"a.b", "axb", false},
		{"(x)", "(x)", true},
		{"(x)", "x", false},
		{"a*", "aaa", false},
		{"a*", "a*", true},
		{"[ab]", "a", false},
		{"^a$", "^a$", true},
		{"\xc3\xbc%", "\xc3\xbcber", true},
	}
	for _, tt := range tests {
		got, err := likeMatch(tt.pattern, tt.value)
		if err != nil {
			t.Errorf("likeMatch(%q, %q): unexpected error %v", tt.pattern, tt.value, err)
			continue
		}
		if got != tt.want {
			t.Errorf("likeMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

// whereXML wraps a comparison in the DAV: prop/literal form of RFC 5323 §5.9.
func whereXML(op, prop, literal string) string {
	return "<d:" + op + "><d:prop><d:" + prop + "/></d:prop><d:literal>" + literal + "</d:literal></d:" + op + ">"
}

// TestParseWhereAST checks the AST shape for the logical operators of
// RFC 5323 §5.9–§5.11 and rejection of elements outside basicsearch.
func TestParseWhereAST(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		want    WhereNode
		wantErr bool
	}{
		{name: "empty", xml: "", want: nil},
		{name: "whitespace only", xml: " \n\t ", want: nil},
		{
			name: "single comparison",
			xml:  whereXML("eq", "displayname", "a.txt"),
			want: compNode{op: "eq", prop: "displayname", literal: "a.txt"},
		},
		{
			name: "default namespace",
			xml:  `<like><prop><displayname/></prop><literal>%.pdf</literal></like>`,
			want: compNode{op: "like", prop: "displayname", literal: "%.pdf"},
		},
		{
			name: "and of two",
			xml:  "<d:and>" + whereXML("gt", "getcontentlength", "10") + whereXML("contains", "displayname", "x") + "</d:and>",
			want: andNode{[]WhereNode{
				compNode{op: "gt", prop: "getcontentlength", literal: "10"},
				compNode{op: "contains", prop: "displayname", literal: "x"},
			}},
		},
		{
			name: "or containing not",
			xml:  "<d:or>" + whereXML("eq", "displayname", "a") + "<d:not>" + whereXML("eq", "displayname", "b") + "</d:not></d:or>",
			want: orNode{[]WhereNode{
				compNode{op: "eq", prop: "displayname", literal: "a"},
				notNode{compNode{op: "eq", prop: "displayname", literal: "b"}},
			}},
		},
		{
			name: "nested and inside or",
			xml:  "<d:or><d:and>" + whereXML("lte", "getcontentlength", "5") + "</d:and>" + whereXML("eq", "displayname", "z") + "</d:or>",
			want: orNode{[]WhereNode{
				andNode{[]WhereNode{compNode{op: "lte", prop: "getcontentlength", literal: "5"}}},
				compNode{op: "eq", prop: "displayname", literal: "z"},
			}},
		},
		{name: "unknown top-level element", xml: "<d:is-collection/>", wantErr: true},
		{name: "unknown element inside and", xml: "<d:and><d:bogus/></d:and>", wantErr: true},
		{name: "unknown element inside not", xml: "<d:not><d:bogus/></d:not>", wantErr: true},
		{name: "unclosed and", xml: "<d:and>" + whereXML("eq", "displayname", "a"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWhereAST([]byte(tt.xml))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseWhereAST: got %#v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWhereAST: unexpected error %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseWhereAST = %#v, want %#v", got, tt.want)
			}
		})
	}
}

// TestEvalWhere evaluates parsed where clauses against an in-memory entry so
// the operator semantics of RFC 5323 §5.9–§5.16 are checked without a walk.
func TestEvalWhere(t *testing.T) {
	mod := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	fp := FileProps{
		Href:          "/docs/Report.PDF",
		LastModified:  mod.Format(http.TimeFormat),
		ModTime:       mod,
		CreationDate:  mod.Format(time.RFC3339),
		ContentLength: 2048,
		ContentType:   "application/pdf",
		DisplayName:   "Report.PDF",
	}
	tests := []struct {
		name    string
		xml     string
		want    bool
		wantErr bool
		typeErr bool // expect *searchTypeError
	}{
		{name: "empty matches all", xml: "", want: true},
		{name: "eq case-insensitive", xml: whereXML("eq", "displayname", "report.pdf"), want: true},
		{name: "eq mismatch", xml: whereXML("eq", "displayname", "other.pdf"), want: false},
		{name: "like suffix", xml: whereXML("like", "displayname", "%.pdf"), want: true},
		{name: "contains", xml: whereXML("contains", "getcontenttype", "PDF"), want: true},
		{name: "int gt", xml: whereXML("gt", "getcontentlength", "1024"), want: true},
		{name: "int lt", xml: whereXML("lt", "getcontentlength", "1024"), want: false},
		{name: "int eq", xml: whereXML("eq", "getcontentlength", "2048"), want: true},
		{name: "int gte boundary", xml: whereXML("gte", "getcontentlength", "2048"), want: true},
		{name: "date eq", xml: whereXML("eq", "getlastmodified", "Fri, 01 Mar 2024 12:00:00 GMT"), want: true},
		{name: "date lt", xml: whereXML("lt", "getlastmodified", "Sat, 02 Mar 2024 00:00:00 GMT"), want: true},
		{name: "iso date gte", xml: whereXML("gte", "creationdate", "2024-03-01T12:00:00Z"), want: true},
		{name: "not", xml: "<d:not>" + whereXML("eq", "displayname", "report.pdf") + "</d:not>", want: false},
		{name: "and all true", xml: "<d:and>" + whereXML("like", "displayname", "%.pdf") + whereXML("gt", "getcontentlength", "1") + "</d:and>", want: true},
		{name: "and one false", xml: "<d:and>" + whereXML("like", "displayname", "%.pdf") + whereXML("gt", "getcontentlength", "4096") + "</d:and>", want: false},
		{name: "or one true", xml: "<d:or>" + whereXML("eq", "displayname", "x") + whereXML("eq", "getcontentlength", "2048") + "</d:or>", want: true},
		{name: "or none true", xml: "<d:or>" + whereXML("eq", "displayname", "x") + whereXML("eq", "displayname", "y") + "</d:or>", want: false},
		{name: "ordered on string", xml: whereXML("lt", "displayname", "z"), wantErr: true, typeErr: true},
		{name: "like on integer", xml: whereXML("like", "getcontentlength", "2%"), wantErr: true},
		{name: "non-integer literal", xml: whereXML("eq", "getcontentlength", "big"), wantErr: true},
		{name: "unparseable date", xml: whereXML("eq", "getlastmodified", "yesterday"), wantErr: true},
		// An error deep in the tree must surface rather than be masked by
		// short-circuiting on an earlier child.
		{name: "error inside or", xml: "<d:or>" + whereXML("eq", "displayname", "x") + whereXML("gt", "displayname", "a") + "</d:or>", wantErr: true, typeErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := parseWhereAST([]byte(tt.xml))
			if err != nil {
				t.Fatalf("parseWhereAST: %v", err)
			}
			got, err := evalWhere(node, fp)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("evalWhere = %v, want error", got)
				}
				var te *searchTypeError
				if tt.typeErr && !errors.As(err, &te) {
					t.Errorf("evalWhere error %v is not a *searchTypeError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("evalWhere: unexpected error %v", err)
			}
			if got != tt.want {
				t.Errorf("evalWhere = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseNResults covers <d:limit><d:nresults> of RFC 5323 §5.17.
func TestParseNResults(t *testing.T) {
	str := func(s string) *string { return &s }
	tests := []struct {
		name    string
		in      *searchLimit
		want    int
		wantErr bool
	}{
		{name: "no limit", in: nil, want: 0},
		{name: "positive", in: &searchLimit{NResults: str("5")}, want: 5},
		{name: "surrounding whitespace", in: &searchLimit{NResults: str("\n 7 ")}, want: 7},
		{name: "zero", in: &searchLimit{NResults: str("0")}, wantErr: true},
		{name: "negative", in: &searchLimit{NResults: str("-3")}, wantErr: true},
		{name: "non-numeric", in: &searchLimit{NResults: str("ten")}, wantErr: true},
		{name: "empty", in: &searchLimit{NResults: str("")}, wantErr: true},
		{name: "missing nresults", in: &searchLimit{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNResults(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseNResults = %d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNResults: unexpected error %v", err)
			}
			if got != tt.want {
				t.Errorf("parseNResults = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestParseOrderBy covers <d:orderby> of RFC 5323 §5.6. Inputs are decoded
// from XML so the test exercises the same struct tags as a real request.
func TestParseOrderBy(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		want    []sortKey
		wantErr bool
	}{
		{name: "none", xml: "", want: nil},
		{
			name: "default ascending",
			xml:  `<d:order><d:prop><d:displayname/></d:prop></d:order>`,
			want: []sortKey{{prop: "displayname"}},
		},
		{
			name: "explicit ascending",
			xml:  `<d:order><d:prop><d:getcontentlength/></d:prop><d:ascending/></d:order>`,
			want: []sortKey{{prop: "getcontentlength"}},
		},
		{
			name: "multiple keys keep order",
			xml: `<d:order><d:prop><d:getlastmodified/></d:prop><d:descending/></d:order>` +
				`<d:order><d:prop><d:getetag/></d:prop></d:order>`,
			want: []sortKey{{prop: "getlastmodified", descending: true}, {prop: "getetag"}},
		},
		{name: "unsupported resourcetype", xml: `<d:order><d:prop><d:resourcetype/></d:prop></d:order>`, wantErr: true},
		{name: "unknown property", xml: `<d:order><d:prop><x:foo xmlns:x="urn:x"/></d:prop></d:order>`, wantErr: true},
		{name: "both directions", xml: `<d:order><d:prop><d:displayname/></d:prop><d:ascending/><d:descending/></d:order>`, wantErr: true},
		{name: "no property", xml: `<d:order><d:prop></d:prop></d:order>`, wantErr: true},
		{name: "two properties", xml: `<d:order><d:prop><d:displayname/><d:getetag/></d:prop></d:order>`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ob struct {
				Orders []searchOrder `xml:"order"`
			}
			doc := `<d:orderby xmlns:d="DAV:">` + tt.xml + `</d:orderby>`
			if err := xml.Unmarshal([]byte(doc), &ob); err != nil {
				t.Fatalf("unmarshal %q: %v", doc, err)
			}
			got, err := parseOrderBy(ob.Orders)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseOrderBy = %v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOrderBy: unexpected error %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseOrderBy = %#v, want %#v", got, tt.want)
			}
		})
	}
}
