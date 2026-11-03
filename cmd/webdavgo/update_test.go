// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import "testing"

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
	}
	for _, tt := range tests {
		if got := releaseURL(tt.version); got != tt.want {
			t.Errorf("releaseURL(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}
