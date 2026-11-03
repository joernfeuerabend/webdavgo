// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestUpdatePending(t *testing.T) {
	failed := &updateStatus{Message: "verification failed"}
	tests := []struct {
		name        string
		requestFile bool
		requested   bool
		status      *updateStatus
		want        bool
	}{
		{"nothing", false, false, nil, false},
		{"request file present", true, false, nil, true},
		{"request file present and requested", true, true, nil, true},
		// The helper has consumed the request and not reported yet.
		{"requested without status", false, true, nil, true},
		// The helper failed and reported it: the page shows the failure.
		{"requested with status", false, true, failed, false},
		{"status from an earlier run", false, false, failed, false},
	}
	for _, tt := range tests {
		if got := updatePending(tt.requestFile, tt.requested, tt.status); got != tt.want {
			t.Errorf("%s: updatePending = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestReleaseURL(t *testing.T) {
	tests := []struct{ version, want string }{
		{"v1.2.3", "https://github.com/joernfeuerabend/webdavgo/releases/tag/v1.2.3"},
		{"v0.1.4", "https://github.com/joernfeuerabend/webdavgo/releases/tag/v0.1.4"},
		{"dev", ""},
		{"v1.2.3-4-gabcdef", ""},
		{"v1.2.3-dirty", ""},
		{"1.2.3", ""},
		{"", ""},
		// Pre-releases have a release page.
		{"v0.1.6-rc.1", "https://github.com/joernfeuerabend/webdavgo/releases/tag/v0.1.6-rc.1"},
		{"v0.1.6-beta.2", "https://github.com/joernfeuerabend/webdavgo/releases/tag/v0.1.6-beta.2"},
		{"v0.1.6-alpha.10", "https://github.com/joernfeuerabend/webdavgo/releases/tag/v0.1.6-alpha.10"},
		// Described builds past a pre-release, and tags outside the
		// pattern, do not.
		{"v0.1.6-rc.1-3-gabc1234", ""},
		{"v0.1.6-rc.1-dirty", ""},
		{"v0.1.6-rc.1-3-gabc1234-dirty", ""},
		{"v0.1.5-3-gabc1234", ""},
		{"v0.1.5-3-gabc1234-dirty", ""},
		{"v0.1.6-rc1", ""},
		{"v0.1.6-rc.01", ""},
		{"v0.1.6-preview.1", ""},
		{"v0.1.6+build.5", ""},
		{"0.1.6-rc.1", ""},
	}
	for _, tt := range tests {
		if got := releaseURL(tt.version); got != tt.want {
			t.Errorf("releaseURL(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in        string
		ok        bool
		str       string // String() of the result
		pre       bool
		described bool
		release   bool // parseReleaseVersion accepts it
	}{
		{"v1.2.3", true, "1.2.3", false, false, true},
		{"1.2.3", true, "1.2.3", false, false, true},
		{"v0.1.6-rc.1", true, "0.1.6-rc.1", true, false, true},
		{"v0.1.6-beta.0", true, "0.1.6-beta.0", true, false, true},
		{"v0.1.6-alpha.12", true, "0.1.6-alpha.12", true, false, true},
		// git describe builds: never a release, never a pre-release.
		{"v0.1.5-3-gabc1234", true, "0.1.5", false, true, false},
		{"v0.1.5-dirty", true, "0.1.5", false, true, false},
		{"v0.1.5-3-gabc1234-dirty", true, "0.1.5", false, true, false},
		// Builds past a pre-release tag keep the tag for the ordering but
		// are described.
		{"v0.1.6-rc.1-3-gabc1234", true, "0.1.6-rc.1", true, true, false},
		{"v0.1.6-rc.1-dirty", true, "0.1.6-rc.1", true, true, false},
		// Valid SemVer pre-release identifiers outside the defined pattern
		// are described builds, not pre-releases.
		{"v0.1.6-rc1", true, "0.1.6", false, true, false},
		{"v0.1.6-rc.01", true, "0.1.6", false, true, false},
		{"v0.1.6-rc", true, "0.1.6", false, true, false},
		{"v0.1.6-rc.1.2", true, "0.1.6", false, true, false},
		{"v0.1.6-preview.1", true, "0.1.6", false, true, false},
		{"v0.1.6-RC.1", true, "0.1.6", false, true, false},
		// Build metadata is kept but does not make a pre-release.
		{"v0.1.6+build.5", true, "0.1.6+build.5", false, false, true},
		{"v0.1.6-rc.2+exp.sha.5114f85", true, "0.1.6-rc.2+exp.sha.5114f85", true, false, true},
		// Not versions.
		{"dev", false, "", false, false, false},
		{"", false, "", false, false, false},
		{"v1.2", false, "", false, false, false},
		{"v1.2.3-", false, "", false, false, false},
		{"v1.2.3-rc.1-", false, "", false, false, false},
		{"v1.2.3+", false, "", false, false, false},
		{"v1.2.3+a..b", false, "", false, false, false},
		{"v1.2.x", false, "", false, false, false},
	}
	for _, tt := range tests {
		v, ok := parseVersion(tt.in)
		if ok != tt.ok {
			t.Errorf("parseVersion(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			continue
		}
		if ok {
			if got := v.String(); got != tt.str {
				t.Errorf("parseVersion(%q) = %q, want %q", tt.in, got, tt.str)
			}
			if v.prerelease() != tt.pre {
				t.Errorf("parseVersion(%q).prerelease() = %v, want %v", tt.in, v.prerelease(), tt.pre)
			}
			if v.described != tt.described {
				t.Errorf("parseVersion(%q).described = %v, want %v", tt.in, v.described, tt.described)
			}
		}
		if _, ok := parseReleaseVersion(tt.in); ok != tt.release {
			t.Errorf("parseReleaseVersion(%q) ok = %v, want %v", tt.in, ok, tt.release)
		}
	}
}

func mustVersion(t *testing.T, s string) semver {
	t.Helper()
	v, ok := parseVersion(s)
	if !ok {
		t.Fatalf("parseVersion(%q) failed", s)
	}
	return v
}

func TestVersionOrdering(t *testing.T) {
	// Strictly ascending.
	ordered := []string{
		"v0.1.5",
		"v0.1.6-alpha.1",
		"v0.1.6-alpha.2",
		"v0.1.6-alpha.10",
		"v0.1.6-beta.1",
		"v0.1.6-beta.2",
		"v0.1.6-beta.11",
		"v0.1.6-rc.1",
		"v0.1.6-rc.2",
		"v0.1.6-rc.10",
		"v0.1.6",
		"v0.1.7-rc.1",
		"v0.1.7",
		"v0.2.0-alpha.0",
		"v0.2.0",
		"v1.0.0-rc.1",
		"v1.0.0",
		"v10.0.0",
	}
	for i, a := range ordered {
		for j, b := range ordered {
			want := cmpInt(i, j)
			if got := mustVersion(t, a).compare(mustVersion(t, b)); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", a, b, got, want)
			}
			if got := mustVersion(t, a).newerThan(mustVersion(t, b)); got != (i > j) {
				t.Errorf("%s.newerThan(%s) = %v, want %v", a, b, got, i > j)
			}
		}
	}

	equal := []struct{ a, b string }{
		// Build metadata does not count.
		{"v0.1.6+build.1", "v0.1.6"},
		{"v0.1.6+build.1", "v0.1.6+build.2"},
		{"v0.1.6-rc.1+a", "v0.1.6-rc.1"},
		// A described build ranks with the version it describes.
		{"v0.1.5-3-gabc1234", "v0.1.5"},
		{"v0.1.5-dirty", "v0.1.5"},
		{"v0.1.6-rc.1-3-gabc1234", "v0.1.6-rc.1"},
	}
	for _, tt := range equal {
		if got := mustVersion(t, tt.a).compare(mustVersion(t, tt.b)); got != 0 {
			t.Errorf("compare(%s, %s) = %d, want 0", tt.a, tt.b, got)
		}
	}

	// A build past v0.1.6-rc.1 is older than rc.2 and the final release.
	past := mustVersion(t, "v0.1.6-rc.1-3-gabc1234")
	for _, s := range []string{"v0.1.6-rc.2", "v0.1.6"} {
		if !mustVersion(t, s).newerThan(past) {
			t.Errorf("%s is not newer than %s", s, past)
		}
	}
}

// TestComparePrerelease covers SemVer 2.0.0 rule 11 beyond the tags
// webdavgo uses, with the example of the specification.
func TestComparePrerelease(t *testing.T) {
	ordered := []string{"alpha", "alpha.1", "alpha.beta", "beta", "beta.2", "beta.11", "rc.1", ""}
	for i, a := range ordered {
		for j, b := range ordered {
			if got, want := comparePrerelease(a, b), cmpInt(i, j); got != want {
				t.Errorf("comparePrerelease(%q, %q) = %d, want %d", a, b, got, want)
			}
		}
	}
	if got := comparePrerelease("rc.9", "rc.10"); got != -1 {
		t.Errorf("comparePrerelease(rc.9, rc.10) = %d, want -1 (numeric, not ASCII)", got)
	}
	if got := comparePrerelease("rc.1", "rc.a"); got != -1 {
		t.Errorf("comparePrerelease(rc.1, rc.a) = %d, want -1 (numeric below alphanumeric)", got)
	}
}

func TestTarballFromSumsPrerelease(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	tests := []struct {
		name    string
		ok      bool
		version string
	}{
		{"webdavgo_0.1.6_linux_" + runtime.GOARCH + ".tar.gz", true, "0.1.6"},
		{"webdavgo_0.1.6-rc.1_linux_" + runtime.GOARCH + ".tar.gz", true, "0.1.6-rc.1"},
		{"webdavgo_0.1.6-beta.12_linux_" + runtime.GOARCH + ".tar.gz", true, "0.1.6-beta.12"},
		// A described build or a leading zero is not a release version.
		{"webdavgo_0.1.6-rc.01_linux_" + runtime.GOARCH + ".tar.gz", false, ""},
		// Outside the name pattern: no tarball for this architecture.
		{"webdavgo_0.1.5-3-gabc1234_linux_" + runtime.GOARCH + ".tar.gz", false, ""},
		{"webdavgo_0.1.6-preview.1_linux_" + runtime.GOARCH + ".tar.gz", false, ""},
	}
	for _, tt := range tests {
		e, err := tarballFromSums([]byte(sum + "  " + tt.name + "\n"))
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok %v", tt.name, err, tt.ok)
			continue
		}
		if err == nil && e.version.String() != tt.version {
			t.Errorf("%s: version %s, want %s", tt.name, e.version, tt.version)
		}
	}
}

func TestUpdateCandidates(t *testing.T) {
	releases := []githubRelease{
		{TagName: "v0.1.4"},
		{TagName: "v0.1.5"},
		{TagName: "v0.1.6-rc.1", Prerelease: true},
		{TagName: "v0.1.6-rc.2", Prerelease: true},
		{TagName: "v0.1.6"},
		{TagName: "v0.1.7-rc.1", Prerelease: true},
		{TagName: "v0.1.7-rc.2", Prerelease: true, Draft: true},
		{TagName: "v0.1.8", Draft: true},
		// Marked as pre-release on GitHub only.
		{TagName: "v0.1.7-beta.1"},
		{TagName: "v0.1.9", Prerelease: true},
		// Never candidates.
		{TagName: "v0.1.6-3-gabc1234"},
		{TagName: "v0.1.6-rc.1-dirty", Prerelease: true},
		{TagName: "v0.1.7+build.1"},
		{TagName: "0.1.7"},
		{TagName: "v00.1.7"},
		{TagName: "nightly", Prerelease: true},
	}
	tags := func(cs []updateCandidate) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.rel.TagName)
		}
		return out
	}
	tests := []struct {
		name        string
		installed   string
		prereleases bool
		newer, held []string
	}{
		{"off, final installed", "v0.1.5", false,
			[]string{"v0.1.6"},
			[]string{"v0.1.9", "v0.1.7-rc.1", "v0.1.7-beta.1", "v0.1.6-rc.2", "v0.1.6-rc.1"}},
		{"on, final installed", "v0.1.5", true,
			[]string{"v0.1.9", "v0.1.7-rc.1", "v0.1.7-beta.1", "v0.1.6", "v0.1.6-rc.2", "v0.1.6-rc.1"}, nil},
		// With the switch off, a server on a pre-release gets the final
		// release once it exists, never another pre-release.
		{"off, pre-release installed", "v0.1.6-rc.1", false,
			[]string{"v0.1.6"},
			[]string{"v0.1.9", "v0.1.7-rc.1", "v0.1.7-beta.1", "v0.1.6-rc.2"}},
		{"on, pre-release installed", "v0.1.6-rc.1", true,
			[]string{"v0.1.9", "v0.1.7-rc.1", "v0.1.7-beta.1", "v0.1.6", "v0.1.6-rc.2"}, nil},
		{"on, build past a pre-release installed", "v0.1.6-rc.2-4-gabc1234", true,
			[]string{"v0.1.9", "v0.1.7-rc.1", "v0.1.7-beta.1", "v0.1.6"}, nil},
		// Never a downgrade: nothing older or equal is a candidate.
		{"off, newest final installed", "v0.1.6", false,
			nil, []string{"v0.1.9", "v0.1.7-rc.1", "v0.1.7-beta.1"}},
		{"on, newest installed", "v0.1.9", true, nil, nil},
		{"on, newer than everything installed", "v1.0.0", true, nil, nil},
	}
	for _, tt := range tests {
		newer, held := updateCandidates(releases, mustVersion(t, tt.installed), tt.prereleases)
		if got := tags(newer); !slices.Equal(got, tt.newer) {
			t.Errorf("%s: candidates %v, want %v", tt.name, got, tt.newer)
		}
		if got := tags(held); !slices.Equal(got, tt.held) {
			t.Errorf("%s: held %v, want %v", tt.name, got, tt.held)
		}
	}
}

func TestSelectUpdate(t *testing.T) {
	old := logger
	t.Cleanup(func() { logger = old })
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	releases := []githubRelease{
		{TagName: "v0.1.5"},
		{TagName: "v0.1.6-rc.1", Prerelease: true},
		{TagName: "v0.1.6-rc.2", Prerelease: true},
		{TagName: "v0.1.6"},
		{TagName: "v0.1.7-rc.1", Prerelease: true},
		{TagName: "v0.1.7-rc.2", Prerelease: true},
		{TagName: "v0.1.8-rc.1", Prerelease: true, Draft: true},
	}
	// verify stands in for verifyRelease: the tags in unsigned fail as a
	// release without SHA256SUMS.minisig does.
	verifier := func(unsigned ...string) func(context.Context, githubRelease, semver) (*availableRelease, error) {
		return func(_ context.Context, r githubRelease, v semver) (*availableRelease, error) {
			if slices.Contains(unsigned, r.TagName) {
				return nil, errors.New("not signed (no " + updateSigFile + " asset)")
			}
			return &availableRelease{Tag: r.TagName, Prerelease: v.prerelease() || r.Prerelease}, nil
		}
	}
	notOffered := func(tag string) string {
		return tag + ": pre-release, not offered while update_prereleases is off"
	}
	unsignedMsg := func(tag string) string { return tag + ": not signed (no " + updateSigFile + " asset)" }
	tests := []struct {
		name        string
		installed   string
		prereleases bool
		unsigned    []string
		want        string // "" for none
		prerelease  bool
		skipped     []string
	}{
		{"off: newest final, newer pre-releases listed", "v0.1.5", false, nil,
			"v0.1.6", false, []string{notOffered("v0.1.7-rc.2"), notOffered("v0.1.7-rc.1")}},
		{"on: newest signed pre-release wins", "v0.1.5", true, nil,
			"v0.1.7-rc.2", true, nil},
		{"on: unsigned newest pre-release is skipped", "v0.1.5", true, []string{"v0.1.7-rc.2"},
			"v0.1.7-rc.1", true, []string{unsignedMsg("v0.1.7-rc.2")}},
		{"on: final release when every newer pre-release is unsigned", "v0.1.5", true, []string{"v0.1.7-rc.2", "v0.1.7-rc.1"},
			"v0.1.6", false, []string{unsignedMsg("v0.1.7-rc.2"), unsignedMsg("v0.1.7-rc.1")}},
		{"off: pre-release installed gets the final release", "v0.1.6-rc.1", false, nil,
			"v0.1.6", false, []string{notOffered("v0.1.7-rc.2"), notOffered("v0.1.7-rc.1")}},
		{"on: pre-release installed gets the newest pre-release", "v0.1.6-rc.1", true, nil,
			"v0.1.7-rc.2", true, nil},
		{"off: unsigned final, pre-releases older than nothing offered are listed", "v0.1.5", false, []string{"v0.1.6"},
			"", false, []string{unsignedMsg("v0.1.6"), notOffered("v0.1.7-rc.2"), notOffered("v0.1.7-rc.1"),
				notOffered("v0.1.6-rc.2"), notOffered("v0.1.6-rc.1")}},
		{"off: up to date", "v0.1.7-rc.2", false, nil, "", false, nil},
		{"on: up to date, drafts never offered", "v0.1.7-rc.2", true, nil, "", false, nil},
	}
	for _, tt := range tests {
		got, skipped := selectUpdate(context.Background(), releases, mustVersion(t, tt.installed), tt.prereleases, verifier(tt.unsigned...))
		gotTag := ""
		if got != nil {
			gotTag = got.Tag
			if got.Prerelease != tt.prerelease {
				t.Errorf("%s: Prerelease = %v, want %v", tt.name, got.Prerelease, tt.prerelease)
			}
		}
		if gotTag != tt.want {
			t.Errorf("%s: offered %q, want %q", tt.name, gotTag, tt.want)
		}
		if !slices.Equal(skipped, tt.skipped) {
			t.Errorf("%s: skipped %q, want %q", tt.name, skipped, tt.skipped)
		}
	}
}

func TestSelectUpdateCandidateLimit(t *testing.T) {
	old := logger
	t.Cleanup(func() { logger = old })
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	var releases []githubRelease
	for i := 1; i <= maxUpdateCandidates+2; i++ {
		releases = append(releases, githubRelease{TagName: fmt.Sprintf("v0.2.0-rc.%d", i), Prerelease: true})
	}
	verified := 0
	never := func(context.Context, githubRelease, semver) (*availableRelease, error) {
		verified++
		return nil, errors.New("not signed")
	}
	got, skipped := selectUpdate(context.Background(), releases, mustVersion(t, "v0.1.5"), true, never)
	if got != nil || verified != maxUpdateCandidates {
		t.Fatalf("offered %v after %d verifications, want none after %d", got, verified, maxUpdateCandidates)
	}
	if last := skipped[len(skipped)-1]; last != "2 older releases were not checked" {
		t.Errorf("last skipped entry %q", last)
	}
}

func TestPrereleaseWithdrawn(t *testing.T) {
	pre := &updateCheck{Latest: &availableRelease{Tag: "v0.1.6-rc.1", Prerelease: true}}
	final := &updateCheck{Latest: &availableRelease{Tag: "v0.1.6"}}
	tests := []struct {
		name        string
		check       *updateCheck
		prereleases bool
		want        bool
	}{
		{"no check", nil, false, false},
		{"nothing offered", &updateCheck{}, false, false},
		{"pre-release, switch on", pre, true, false},
		{"pre-release, switch turned off", pre, false, true},
		{"final release, switch off", final, false, false},
	}
	for _, tt := range tests {
		if got := prereleaseWithdrawn(tt.check, tt.prereleases); got != tt.want {
			t.Errorf("%s: prereleaseWithdrawn = %v, want %v", tt.name, got, tt.want)
		}
	}
}
