// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestInstallUnitText checks that the log directory comes from systemd and
// that no hardening line was lost on the way.
func TestInstallUnitText(t *testing.T) {
	lines := map[string]bool{}
	for _, l := range strings.Split(installUnitText, "\n") {
		lines[l] = true
	}
	for _, want := range []string{
		"LogsDirectory=webdavgo", "LogsDirectoryMode=0750", "ReadWritePaths=/var/lib/webdavgo",
		"User=webdavgo", "Group=webdavgo", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
		"PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
		"ProtectKernelLogs=yes", "ProtectControlGroups=yes",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK", "RestrictNamespaces=yes",
		"LockPersonality=yes", "MemoryDenyWriteExecute=yes", "SystemCallArchitectures=native",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"UMask=0027", "RestrictSUIDSGID=yes", "RestrictRealtime=yes", "ProtectClock=yes",
		"ProtectHostname=yes", "ProtectProc=invisible", "SystemCallFilter=@system-service",
		"SystemCallErrorNumber=EPERM", "StandardOutput=journal", "StandardError=journal",
	} {
		if !lines[want] {
			t.Errorf("unit lacks %q", want)
		}
	}
	if n := strings.Count(installUnitText, "ReadWritePaths="); n != 1 || strings.Contains(installUnitText, "ReadWritePaths=/var/log") {
		t.Errorf("the log directory must come from LogsDirectory=, not ReadWritePaths= (%d ReadWritePaths lines)", n)
	}
	if strings.Contains(installUnitText, "Logs go to journald") {
		t.Error("unit comment still says that all logs go to journald")
	}
}

func TestInstallLogrotateText(t *testing.T) {
	want := `/var/log/webdavgo/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    su webdavgo webdavgo
    create 0640 webdavgo webdavgo
    sharedscripts
    postrotate
        systemctl kill -s USR1 webdavgo.service >/dev/null 2>&1 || true
    endscript
}
`
	if !strings.HasSuffix(installLogrotateText, "\n"+want) {
		t.Errorf("logrotate text:\n%s\nwant it to end with:\n%s", installLogrotateText, want)
	}
	for _, l := range strings.Split(installLogrotateText, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") && !strings.Contains(want, l) {
			t.Errorf("unexpected line %q", l)
		}
	}
}

// TestInstallConfigLogKeys: the written config must name files that the
// logrotate pattern covers, and pass validation.
func TestInstallConfigLogKeys(t *testing.T) {
	c := defaultConfig()
	if _, err := toml.Decode(installConfigText, &c); err != nil {
		t.Fatal(err)
	}
	if c.AccessLog != installAccessLog || c.ServerLog != installServerLog {
		t.Errorf("config sets access_log=%q server_log=%q", c.AccessLog, c.ServerLog)
	}
	for _, p := range []string{c.AccessLog, c.ServerLog} {
		if ok, _ := filepath.Match(installLogs+"/*.log", p); !ok {
			t.Errorf("%s is not rotated by %s", p, installLogrotate)
		}
	}
	if err := c.validate(); err != nil {
		t.Errorf("installed config does not validate: %v", err)
	}
}

func TestMissingLogKeys(t *testing.T) {
	dir := t.TempDir()
	tests := []struct{ config, want string }{
		{`data_dir = "/var/lib/webdavgo"`, "access_log and server_log"},
		{`access_log = "/var/log/webdavgo/access.log"`, "server_log"},
		{installConfigText, ""},
	}
	for i, tt := range tests {
		p := filepath.Join(dir, "c.toml")
		if err := os.WriteFile(p, []byte(tt.config), 0600); err != nil {
			t.Fatal(err)
		}
		if got := missingLogKeys(p); got != tt.want {
			t.Errorf("case %d: missingLogKeys = %q, want %q", i, got, tt.want)
		}
	}
}
