// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// update.go is the Update page of the admin UI and what it shares with the
// root helper (updatehelper.go).
//
// Nothing here contacts the network on its own. GitHub is queried only when
// the admin clicks "Check for updates". A release is offered only if it is
// neither a draft nor a pre-release, is newer than the running version, and
// has a SHA256SUMS.minisig asset that verifies against an embedded release
// key (minisign.go).
//
// "Install update" downloads the tarball for this architecture, SHA256SUMS
// and SHA256SUMS.minisig into updateDir and places updateRequestFile there.
// The systemd path unit webdavgo-update.path then starts
// webdavgo-update.service, which runs the installed, root-owned binary as
// "webdavgo apply-update". The helper checks everything again on its own,
// installs the new binary, restarts the service and writes
// updateStatusFile, which this page shows.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	updateRepo = "joernfeuerabend/webdavgo"
	// updateDir belongs to the service user. The helper trusts nothing in it.
	updateDir         = installData + "/update"
	updateRequestFile = "request"
	updateStatusFile  = "status.json"
	updateSumsFile    = "SHA256SUMS"
	updateSigFile     = "SHA256SUMS.minisig"

	// The helper units written by "webdavgo install" when the installation
	// is prepared for updates via the web UI.
	updatePathUnit    = "/etc/systemd/system/webdavgo-update.path"
	updateServiceUnit = "/etc/systemd/system/webdavgo-update.service"

	// previousBinDir keeps the binary an update replaced. It is root-owned
	// and outside the service's writable paths.
	previousBinDir = "/usr/local/lib/webdavgo"
	previousBin    = previousBinDir + "/webdavgo.previous"

	maxUpdateSums    = 64 << 10
	maxUpdateSig     = 4 << 10
	maxUpdateTarball = 256 << 20
	maxUpdateBinary  = 512 << 20
	// maxUpdateCandidates bounds how many newer releases a check
	// downloads signatures for before it gives up.
	maxUpdateCandidates = 5
)

const updatePathUnitText = `# Written by "webdavgo install". A later install overwrites it.
[Unit]
Description=webdavgo update request watch

[Path]
# The admin UI places this file once it has downloaded an update.
PathExists=/var/lib/webdavgo/update/request
Unit=webdavgo-update.service

[Install]
WantedBy=paths.target
`

// updateServiceUnitText runs the installed binary as root. It is started
// by webdavgo-update.path only. The helper needs no network: everything it
// installs has been downloaded by the service already.
const updateServiceUnitText = `# Written by "webdavgo install". A later install overwrites it.
[Unit]
Description=webdavgo update helper

[Service]
Type=oneshot
# The root-owned installed binary verifies the signature, the checksum and
# the version of the downloaded release itself, and trusts nothing else the
# webdavgo service placed in /var/lib/webdavgo/update.
ExecStart=/usr/local/bin/webdavgo apply-update
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateNetwork=yes
PrivateTmp=yes
ProtectHome=yes
`

// ---- versions ----------------------------------------------------------------

// semver is MAJOR.MINOR.PATCH. described marks a build past that release,
// such as "v1.2.3-4-gabcdef" or "v1.2.3-dirty" from git describe.
type semver struct {
	major, minor, patch int
	described           bool
}

func (v semver) String() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch) }

// newerThan compares the release numbers only: a build past v1.2.3 is not
// older than v1.2.3, and v1.2.4 is newer than both.
func (v semver) newerThan(o semver) bool {
	if v.major != o.major {
		return v.major > o.major
	}
	if v.minor != o.minor {
		return v.minor > o.minor
	}
	return v.patch > o.patch
}

// parseVersion accepts "v1.2.3" or "1.2.3", optionally followed by a git
// describe suffix ("-..."). "dev" and other builds are not versions.
func parseVersion(s string) (semver, bool) {
	core, rest, hasRest := strings.Cut(strings.TrimPrefix(s, "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 || (hasRest && rest == "") {
		return semver{}, false
	}
	var n [3]int
	for i, p := range parts {
		if p == "" || strings.TrimLeft(p, "0123456789") != "" || len(p) > 9 {
			return semver{}, false
		}
		n[i], _ = strconv.Atoi(p)
	}
	return semver{major: n[0], minor: n[1], patch: n[2], described: hasRest}, true
}

// parseReleaseVersion accepts exact release versions only.
func parseReleaseVersion(s string) (semver, bool) {
	v, ok := parseVersion(s)
	return v, ok && !v.described
}

// installedVersion is the version of this binary, which for the helper is
// the installed one.
func installedVersion() (semver, error) {
	v, ok := parseVersion(version)
	if !ok {
		return semver{}, fmt.Errorf("the running version %q is not a release version, so it cannot be compared with releases", version)
	}
	return v, nil
}

// ---- signed checksums ----------------------------------------------------------

// releaseTarball is the entry of a signed SHA256SUMS for this architecture.
type releaseTarball struct {
	name    string
	sum     [32]byte
	version semver
}

var tarballNameRE = regexp.MustCompile(`^webdavgo_([0-9]+\.[0-9]+\.[0-9]+)_linux_([a-z0-9]+)\.tar\.gz$`)

// tarballFromSums finds the tarball for runtime.GOARCH in a SHA256SUMS
// file as sha256sum writes it ("<hex>  <name>", or "<hex> *<name>").
func tarballFromSums(sums []byte) (releaseTarball, error) {
	var found []releaseTarball
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		hexSum, name, ok := strings.Cut(line, " ")
		if !ok {
			return releaseTarball{}, errors.New("SHA256SUMS has a malformed line")
		}
		name = strings.TrimPrefix(strings.TrimPrefix(name, " "), "*")
		m := tarballNameRE.FindStringSubmatch(name)
		if m == nil || m[2] != runtime.GOARCH {
			continue
		}
		raw, err := hex.DecodeString(hexSum)
		if err != nil || len(raw) != sha256.Size {
			return releaseTarball{}, fmt.Errorf("SHA256SUMS has a malformed checksum for %s", name)
		}
		v, ok := parseReleaseVersion(m[1])
		if !ok {
			return releaseTarball{}, fmt.Errorf("SHA256SUMS lists %s, whose version is not valid", name)
		}
		t := releaseTarball{name: name, version: v}
		copy(t.sum[:], raw)
		found = append(found, t)
	}
	switch len(found) {
	case 0:
		return releaseTarball{}, fmt.Errorf("SHA256SUMS lists no tarball for linux/%s", runtime.GOARCH)
	case 1:
		return found[0], nil
	default:
		return releaseTarball{}, fmt.Errorf("SHA256SUMS lists more than one tarball for linux/%s", runtime.GOARCH)
	}
}

// verifySignedSums checks the minisign signature of sums against the
// embedded release keys and returns the tarball entry for this
// architecture.
func verifySignedSums(sums, sig []byte) (releaseTarball, error) {
	keys, err := releaseKeys()
	if err != nil {
		return releaseTarball{}, err
	}
	if _, err := minisignVerify(keys, sums, sig); err != nil {
		return releaseTarball{}, fmt.Errorf("SHA256SUMS.minisig: %w", err)
	}
	return tarballFromSums(sums)
}

// ---- status shared with the helper ----------------------------------------------

// updateStatus is what the helper reports in updateStatusFile.
type updateStatus struct {
	Time    time.Time `json:"time"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	From    string    `json:"from,omitempty"`
	To      string    `json:"to,omitempty"`
}

// ---- checking GitHub ----------------------------------------------------------------

type githubAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type githubRelease struct {
	TagName    string        `json:"tag_name"`
	HTMLURL    string        `json:"html_url"`
	Draft      bool          `json:"draft"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

func (r githubRelease) asset(name string) (githubAsset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return githubAsset{}, false
}

// availableRelease is a release that passed every check.
type availableRelease struct {
	Tag      string
	NotesURL string
	tarball  githubAsset
	entry    releaseTarball
	sumsData []byte
	sigData  []byte
}

// updateCheck is the result of the last check.
type updateCheck struct {
	Time   time.Time
	Err    string
	Latest *availableRelease
	// Skipped explains newer releases that were not offered.
	Skipped []string
}

var updateState struct {
	sync.Mutex
	check      *updateCheck
	installing bool
	// requested is set once this process has handed an update to the
	// helper. The helper removes the request file as its first step,
	// often before the browser follows the redirect to the Update page.
	// Until the helper writes updateStatusFile, the page still shows the
	// update as pending. A successful update restarts the process, which
	// clears the flag.
	requested bool
}

var updateClient = &http.Client{Transport: http.DefaultTransport}

// updateGet fetches url with at most limit bytes of body.
func updateGet(ctx context.Context, url, accept string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "webdavgo/"+version)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := updateClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return data, nil
}

// checkForUpdate asks GitHub for the newest release this binary can update
// to.
func checkForUpdate(ctx context.Context) *updateCheck {
	res := &updateCheck{Time: time.Now()}
	installed, err := installedVersion()
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if _, err := releaseKeys(); err != nil {
		res.Err = err.Error()
		return res
	}
	data, err := updateGet(ctx, "https://api.github.com/repos/"+updateRepo+"/releases?per_page=30",
		"application/vnd.github+json", 8<<20)
	if err != nil {
		res.Err = "cannot query GitHub: " + err.Error()
		return res
	}
	var releases []githubRelease
	if err := json.Unmarshal(data, &releases); err != nil {
		res.Err = "cannot read the GitHub answer: " + err.Error()
		return res
	}
	type candidate struct {
		rel githubRelease
		v   semver
	}
	var newer []candidate
	for _, r := range releases {
		if r.Draft || r.Prerelease {
			continue
		}
		v, ok := parseReleaseVersion(r.TagName)
		if !ok || !strings.HasPrefix(r.TagName, "v") || !v.newerThan(installed) {
			continue
		}
		newer = append(newer, candidate{r, v})
	}
	slices.SortFunc(newer, func(a, b candidate) int {
		switch {
		case a.v.newerThan(b.v):
			return -1
		case b.v.newerThan(a.v):
			return 1
		}
		return 0
	})
	for i, c := range newer {
		if i == maxUpdateCandidates {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%d older releases were not checked", len(newer)-i))
			break
		}
		a, err := verifyRelease(ctx, c.rel, c.v)
		if err != nil {
			res.Skipped = append(res.Skipped, c.rel.TagName+": "+err.Error())
			logger.Info("update check: release not offered", "tag", c.rel.TagName, "reason", err)
			continue
		}
		res.Latest = a
		break
	}
	return res
}

// verifyRelease downloads and verifies the signed checksums of r.
func verifyRelease(ctx context.Context, r githubRelease, v semver) (*availableRelease, error) {
	sums, ok := r.asset(updateSumsFile)
	if !ok {
		return nil, errors.New("no " + updateSumsFile + " asset")
	}
	sig, ok := r.asset(updateSigFile)
	if !ok {
		return nil, errors.New("not signed (no " + updateSigFile + " asset)")
	}
	sumsData, err := updateGet(ctx, sums.URL, "", maxUpdateSums)
	if err != nil {
		return nil, err
	}
	sigData, err := updateGet(ctx, sig.URL, "", maxUpdateSig)
	if err != nil {
		return nil, err
	}
	entry, err := verifySignedSums(sumsData, sigData)
	if err != nil {
		return nil, err
	}
	if entry.version != v {
		return nil, fmt.Errorf("the signed SHA256SUMS is for version %s, not for this release", entry.version)
	}
	tarball, ok := r.asset(entry.name)
	if !ok {
		return nil, errors.New("no asset " + entry.name)
	}
	return &availableRelease{
		Tag: r.TagName, NotesURL: r.HTMLURL,
		tarball: tarball, entry: entry, sumsData: sumsData, sigData: sigData,
	}, nil
}

// ---- installing ----------------------------------------------------------------------

// updateHelperInstalled reports whether "webdavgo install" set up the root
// helper units.
func updateHelperInstalled() bool {
	return fileExists(updatePathUnit) && fileExists(updateServiceUnit)
}

func updateRequestPending() bool {
	_, err := os.Lstat(filepath.Join(updateDir, updateRequestFile))
	return err == nil
}

// installBlocked explains why "Install update" is not available, or
// returns "".
func installBlocked() string {
	switch {
	case containerMode:
		return "webdavgo runs in a container. Updates come as a new image tag: pull the new tag and recreate the container with it."
	case !updateHelperInstalled():
		return "This installation is not prepared for updates via the web UI. Running \"sudo webdavgo install\" again can enable it."
	}
	return ""
}

// requestUpdate downloads a and hands it to the helper. The service checks
// the download as well, so that a broken download is reported here and not
// only by the helper.
func requestUpdate(ctx context.Context, a *availableRelease) error {
	tarball, err := updateGet(ctx, a.tarball.URL, "", maxUpdateTarball)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if sha256.Sum256(tarball) != a.entry.sum {
		return fmt.Errorf("the SHA-256 of %s does not match the signed SHA256SUMS", a.entry.name)
	}
	if err := os.MkdirAll(updateDir, 0750); err != nil {
		return err
	}
	// Leftovers of an earlier attempt, including the last status: the page
	// shows the pending request until the helper writes a new one.
	entries, err := os.ReadDir(updateDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(updateDir, e.Name())); err != nil {
			return err
		}
	}
	files := []struct {
		name string
		data []byte
	}{
		{updateSumsFile, a.sumsData},
		{updateSigFile, a.sigData},
		{a.entry.name, tarball},
	}
	for _, f := range files {
		if err := writeAtomic(filepath.Join(updateDir, f.name), f.data, 0640); err != nil {
			return err
		}
	}
	// Last, so the helper never starts on a partial download. The content
	// is for the operator only, the helper ignores it.
	return writeAtomic(filepath.Join(updateDir, updateRequestFile), []byte(a.Tag+"\n"), 0640)
}

// readUpdateStatus returns the helper's last report, or nil.
func readUpdateStatus() *updateStatus {
	f, err := os.Open(filepath.Join(updateDir, updateStatusFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var st updateStatus
	if err := json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&st); err != nil {
		return &updateStatus{Message: "the status file of the update helper cannot be read: " + err.Error()}
	}
	return &st
}

// updatePending reports whether the Update page shows an update as handed
// to the helper and not finished yet: the request file is still there, or
// this process requested an update and the helper has not reported yet.
func updatePending(requestFile, requested bool, status *updateStatus) bool {
	return requestFile || (requested && status == nil)
}

// ---- handlers ------------------------------------------------------------------------

func renderUpdate(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	updateState.Lock()
	check := updateState.check
	requested := updateState.requested
	updateState.Unlock()
	st := readUpdateStatus()
	pending := updatePending(updateRequestPending(), requested, st)
	blocked := installBlocked()
	data := map[string]any{
		"Page":       "update",
		"Version":    version,
		"Error":      errMsg,
		"Check":      check,
		"Pending":    pending,
		"Blocked":    blocked,
		"Status":     st,
		"CanInstall": check != nil && check.Latest != nil && blocked == "" && !pending,
	}
	if check != nil {
		data["CheckedAt"] = formatStatusTime(check.Time)
	}
	if st != nil && !st.Time.IsZero() {
		data["StatusAt"] = formatStatusTime(st.Time)
	}
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
	}
	renderPage(w, r, "update", data)
}

func handleUpdateGET(w http.ResponseWriter, r *http.Request) {
	renderUpdate(w, r, http.StatusOK, "")
}

func handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res := checkForUpdate(ctx)
	updateState.Lock()
	updateState.check = res
	updateState.Unlock()
	switch {
	case res.Err != "":
		logger.Warn("update check failed", "err", res.Err, "by", currentUser(r))
	case res.Latest != nil:
		logger.Info("update check: update available", "installed", version, "available", res.Latest.Tag, "by", currentUser(r))
	default:
		logger.Info("update check: no update available", "installed", version, "by", currentUser(r))
	}
	http.Redirect(w, r, "/admin/update", http.StatusSeeOther)
}

func handleUpdateInstall(w http.ResponseWriter, r *http.Request) {
	if msg := installBlocked(); msg != "" {
		renderUpdate(w, r, http.StatusConflict, msg)
		return
	}
	updateState.Lock()
	check := updateState.check
	requested := updateState.requested
	updateState.Unlock()
	if updatePending(updateRequestPending(), requested, readUpdateStatus()) {
		renderUpdate(w, r, http.StatusConflict, "An update request is already waiting for the update helper.")
		return
	}
	updateState.Lock()
	busy := updateState.installing
	if !busy {
		updateState.installing = true
		// requestUpdate removes the last status first. If it then fails,
		// an earlier request must not leave the page waiting for a
		// report that never comes.
		updateState.requested = false
	}
	updateState.Unlock()
	if busy {
		renderUpdate(w, r, http.StatusConflict, "An update is being downloaded already.")
		return
	}
	defer func() {
		updateState.Lock()
		updateState.installing = false
		updateState.Unlock()
	}()
	if check == nil || check.Latest == nil {
		renderUpdate(w, r, http.StatusConflict, "No update is available. Check for updates first.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	if err := requestUpdate(ctx, check.Latest); err != nil {
		logger.Error("update request failed", "tag", check.Latest.Tag, "err", err, "by", currentUser(r))
		renderUpdate(w, r, http.StatusBadGateway, "The update could not be prepared: "+err.Error())
		return
	}
	updateState.Lock()
	updateState.requested = true
	updateState.Unlock()
	logger.Info("update requested, the update helper installs it and restarts the service",
		"installed", version, "tag", check.Latest.Tag, "by", currentUser(r))
	http.Redirect(w, r, "/admin/update", http.StatusSeeOther)
}
