// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// install.go – "webdavgo install" and "webdavgo uninstall": the one console
// step of a deployment on Linux with systemd. Everything after it happens in
// the browser (setup, TOTP, Settings → TLS & domain).
//
// Both commands print their plan before they change anything. -root DIR
// prefixes every path and skips the user and systemctl steps, so that the
// generated files can be checked without root (test.sh does).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	serviceUser   = "webdavgo"
	serviceName   = "webdavgo"
	installBin    = "/usr/local/bin/webdavgo"
	installEtc    = "/etc/webdavgo"
	installConfig = defaultConfigFile
	// installOldConfig is what older versions installed; install creates
	// installConfig from it instead of from the example.
	installOldConfig = "/etc/webdavgo/" + oldConfigFileName
	installData      = "/var/lib/webdavgo"
	installUnit      = "/etc/systemd/system/webdavgo.service"
	// installLogs is created by systemd (LogsDirectory= in the unit), not
	// by install, so it gets the service user and is writable in the
	// sandbox.
	installLogs      = "/var/log/webdavgo"
	installLogrotate = "/etc/logrotate.d/webdavgo"
	installAccessLog = installLogs + "/access.log"
	installServerLog = installLogs + "/webdavgo.log"
)

//go:embed webdavgo.example.conf
var exampleConfigText string

// installConfigText is the example with what a service needs set, written
// once and never overwritten: it is the operator's file from then on, which
// the admin UI also saves to. require_tls keeps WebDAV off the network in
// plain HTTP until the Settings page's certificate request has set up TLS.
// access_log and server_log must match installLogrotate's pattern, or the
// files are never rotated.
var installConfigText = setConfLines(exampleConfigText, map[string]string{
	"data_dir":    tomlString(installData),
	"require_tls": "true",
	"access_log":  tomlString(installAccessLog),
	"server_log":  tomlString(installServerLog),
})

// installUnitText is the hardened systemd unit. The service can write only
// its data, config and log directories and bind ports below 1024 (443 for
// ACME), nothing else. The config directory is writable because the admin
// UI saves to the config file (temporary file and rename). AF_NETLINK is needed to list the network interfaces for
// the admin certificate and the setup URLs.
const installUnitText = `# Written by "webdavgo install"; a later install overwrites it.
[Unit]
Description=webdavgo WebDAV server
After=network-online.target
Wants=network-online.target

[Service]
# The server reports READY=1 once its listeners serve, and pings the
# watchdog every WatchdogSec/2 while it is live; a missed ping restarts it.
Type=notify
WatchdogSec=30s
User=webdavgo
Group=webdavgo
ExecStart=/usr/local/bin/webdavgo -config /etc/webdavgo/webdavgo.conf
Restart=on-failure
RestartSec=5s
# The config's access_log and server_log go to /var/log/webdavgo. Records
# before the config is loaded, and a copy of every Error record, go to
# journald: journalctl -u webdavgo
StandardOutput=journal
StandardError=journal

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/webdavgo /etc/webdavgo
# systemd creates /var/log/webdavgo for the service user and makes it
# writable despite ProtectSystem=strict.
LogsDirectory=webdavgo
LogsDirectoryMode=0750
# Files the service creates are not readable for others.
UMask=0027
RestrictSUIDSGID=yes
RestrictRealtime=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`

// installLogrotateText rotates the files of installConfigText. su makes
// logrotate act as the service user in its directory; the postrotate
// script still runs as root, as systemctl kill needs. webdavgo starts no
// child processes, so signalling the whole unit reaches only the server,
// and the command works on every systemd version.
const installLogrotateText = `# Written by "webdavgo install"; a later install overwrites it.
/var/log/webdavgo/*.log {
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

// planStep is one announced change; do is nil for steps that only inform.
type planStep struct {
	desc string
	do   func() error
}

// runPlan prints every step, then runs them in order. It returns the
// process exit code.
func runPlan(title string, steps []planStep, confirm func() bool) int {
	fmt.Println(title)
	for i, s := range steps {
		fmt.Printf("  %d. %s\n", i+1, s.desc)
	}
	if confirm != nil && !confirm() {
		fmt.Println("Aborted; nothing was changed.")
		return 1
	}
	for _, s := range steps {
		if s.do == nil {
			continue
		}
		if err := s.do(); err != nil {
			logger.Error("step failed", "step", s.desc, "err", err)
			return 1
		}
	}
	return 0
}

// systemChecks refuses to touch a real system unless it is Linux with
// systemd and we are root. With -root nothing outside that directory is
// changed, so the checks do not apply.
func systemChecks(command string) bool {
	if runtime.GOOS != "linux" {
		logger.Error(command+" supports Linux with systemd only; on other systems start webdavgo by hand",
			"os", runtime.GOOS)
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		logger.Error(command+" needs systemd, but systemctl was not found", "err", err)
		return false
	}
	if os.Geteuid() != 0 {
		logger.Error(command + " must run as root, e.g. sudo ./webdavgo " + command)
		return false
	}
	return true
}

func runInstall(args []string) int {
	fset := flag.NewFlagSet("webdavgo install", flag.ContinueOnError)
	root := fset.String("root", "/", "prefix for every path; other than / skips user creation and systemctl")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() > 0 {
		logger.Error("usage: webdavgo install [-root dir]")
		return 2
	}
	system := filepath.Clean(*root) == "/"
	if system && !systemChecks("install") {
		return 1
	}
	at := func(p string) string { return filepath.Join(*root, p) }

	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		logger.Error("cannot locate the running binary", "err", err)
		return 1
	}

	var steps []planStep
	binChanged := false
	if same, _ := sameContent(exe, at(installBin)); same {
		steps = append(steps, planStep{desc: "keep " + at(installBin) + " (already this binary)"})
	} else {
		binChanged = true
		steps = append(steps, planStep{
			desc: "copy " + exe + " to " + at(installBin) + " (temporary file, then rename)",
			do:   func() error { return copyAtomic(exe, at(installBin), 0755) },
		})
	}

	if system {
		_, uerr := user.Lookup(serviceUser)
		_, gerr := user.LookupGroup(serviceUser)
		if uerr == nil && gerr == nil {
			steps = append(steps, planStep{desc: "keep the existing system user and group " + serviceUser})
		} else {
			steps = append(steps, planStep{
				desc: "create the system user and group " + serviceUser + " (no login shell, no home directory)",
				do:   createServiceUser,
			})
		}
	} else {
		steps = append(steps, planStep{desc: "skip creating the system user " + serviceUser + " (-root)"})
	}

	// The service user owns the config directory and file: the admin UI
	// saves to the file through a temporary file and a rename.
	steps = append(steps,
		dirStep(at(installEtc), serviceUser, serviceUser, system),
		dirStep(at(installData), serviceUser, serviceUser, system),
	)

	conf := at(installConfig)
	owned := func() error {
		if err := os.Chmod(conf, 0640); err != nil {
			return fmt.Errorf("chmod %s: %w", conf, err)
		}
		if system {
			return chownTo(conf, serviceUser, serviceUser)
		}
		return nil
	}
	ownership := serviceUser + ":" + serviceUser + ", 0640"
	logHint := func(path string) string {
		// An unset key means its default, which is the installed path.
		switch missing := missingLogKeys(path); missing {
		case "":
			return ""
		case "access_log and server_log":
			return "; it does not set access_log and server_log, so their defaults apply: both log files are written under " +
				installLogs + " (" + filepath.Base(installAccessLog) + ", " + filepath.Base(installServerLog) + ")"
		case "access_log":
			return "; it does not set access_log, so its default applies: " + installAccessLog
		default:
			return "; it does not set server_log, so its default applies: " + installServerLog
		}
	}
	switch {
	case fileExists(conf):
		steps = append(steps, planStep{
			desc: "keep " + conf + " (an existing config is never overwritten; owner and mode enforced: " +
				ownership + ")" + logHint(conf),
			do: owned,
		})
	case fileExists(at(installOldConfig)):
		old := at(installOldConfig)
		steps = append(steps, planStep{
			desc: "create " + conf + " from " + old + " (" + ownership + "; " + old + " is left as it is)" + logHint(old),
			do: func() error {
				if err := migrateConfigFile(old, conf); err != nil {
					return err
				}
				logger.Info("config file migrated; the old file is left as it is", "from", old, "to", conf)
				return owned()
			},
		})
	default:
		steps = append(steps, planStep{
			desc: "write " + conf + " from webdavgo.example.conf (" + ownership + "; data_dir = " + installData +
				", require_tls = true, access_log and server_log in " + installLogs + ")",
			do: func() error {
				if err := writeAtomic(conf, []byte(installConfigText), 0640); err != nil {
					return err
				}
				return owned()
			},
		})
	}

	unitChanged := true
	if old, err := os.ReadFile(at(installUnit)); err == nil && string(old) == installUnitText {
		unitChanged = false
		steps = append(steps, planStep{desc: "keep " + at(installUnit) + " (unchanged)"})
	} else {
		steps = append(steps, planStep{
			desc: "write the hardened systemd unit " + at(installUnit),
			do:   func() error { return writeAtomic(at(installUnit), []byte(installUnitText), 0644) },
		})
	}

	logrotate := planStep{
		desc: "write " + at(installLogrotate) + " (0644; daily, 14 days, SIGUSR1 reopens the files)",
		do:   func() error { return writeAtomic(at(installLogrotate), []byte(installLogrotateText), 0644) },
	}
	if old, err := os.ReadFile(at(installLogrotate)); err == nil && string(old) == installLogrotateText {
		logrotate = planStep{desc: "keep " + at(installLogrotate) + " (unchanged)"}
	}
	if !logrotateInstalled() {
		logrotate.desc += "; logrotate is not installed: without it the log files are never rotated"
	}
	steps = append(steps, logrotate)

	if system {
		wasActive := exec.Command("systemctl", "is-active", "--quiet", serviceName).Run() == nil
		steps = append(steps, planStep{
			desc: "systemctl daemon-reload and systemctl enable --now " + serviceName,
			do: func() error {
				if err := systemctl("daemon-reload"); err != nil {
					return err
				}
				return systemctl("enable", "--now", serviceName)
			},
		})
		if wasActive && (binChanged || unitChanged) {
			steps = append(steps, planStep{
				desc: "systemctl restart " + serviceName + " (it was running; picks up the new binary or unit)",
				do:   func() error { return systemctl("restart", serviceName) },
			})
		}
		steps = append(steps, planStep{
			desc: "show the admin URLs, the admin certificate fingerprint and, if no admin exists yet, the setup URL (webdavgo setup-info)",
			do:   showSetupInfo,
		})
	} else {
		steps = append(steps, planStep{desc: "skip systemctl and setup-info (-root); after starting the service run: webdavgo setup-info -config " + installConfig})
	}

	return runPlan("webdavgo install will:", steps, nil)
}

// missingLogKeys names the log keys an existing config does not set, e.g.
// "access_log and server_log", or returns "" when both are set. A key set
// to "" counts as set: it deliberately sends its records to stdout.
func missingLogKeys(config string) string {
	var c struct {
		AccessLog string `toml:"access_log"`
		ServerLog string `toml:"server_log"`
	}
	// An unreadable config is reported by the service itself; here it
	// only means the keys cannot be confirmed.
	md, _ := toml.DecodeFile(config, &c)
	var missing []string
	for _, key := range []string{"access_log", "server_log"} {
		if !md.IsDefined(key) {
			missing = append(missing, key)
		}
	}
	return strings.Join(missing, " and ")
}

// logrotateInstalled looks in /usr/sbin too: sudo's PATH usually has it,
// a plain user's often does not.
func logrotateInstalled() bool {
	if _, err := exec.LookPath("logrotate"); err == nil {
		return true
	}
	return fileExists("/usr/sbin/logrotate")
}

// dirStep creates dir or fixes its owner and mode; the contents of an
// existing directory are left alone.
func dirStep(dir, owner, group string, system bool) planStep {
	verb := "create"
	if _, err := os.Stat(dir); err == nil {
		verb = "keep (owner and mode enforced)"
	}
	desc := fmt.Sprintf("%s %s (%s:%s, 0750)", verb, dir, owner, group)
	return planStep{desc: desc, do: func() error {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0750); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
		if system {
			return chownTo(dir, owner, group)
		}
		return nil
	}}
}

func createServiceUser() error {
	if _, err := user.LookupGroup(serviceUser); err != nil {
		if out, err := exec.Command("groupadd", "--system", serviceUser).CombinedOutput(); err != nil {
			return fmt.Errorf("groupadd: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	if _, err := user.Lookup(serviceUser); err != nil {
		shell := "/usr/sbin/nologin"
		if _, err := os.Stat(shell); err != nil {
			shell = "/sbin/nologin"
		}
		out, err := exec.Command("useradd", "--system", "--gid", serviceUser, "--no-create-home",
			"--home-dir", "/nonexistent", "--shell", shell, serviceUser).CombinedOutput()
		if err != nil {
			return fmt.Errorf("useradd: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func chownTo(path, owner, group string) error {
	u, err := user.Lookup(owner)
	if err != nil {
		return fmt.Errorf("look up user %s: %w", owner, err)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("look up group %s: %w", group, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(g.Gid)
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

// schemaWait bounds how long install waits for the restarted service to
// migrate the database. The migration first copies the whole database as a
// backup, so a large one takes a while.
const schemaWait = 2 * time.Minute

// showSetupInfo waits until the freshly started service has created its
// database and admin certificate, then prints what setup-info prints. After
// an upgrade both already exist, but the service may still be migrating the
// database; setup-info then fails with schemaPendingHint and is retried
// quietly, so only the final answer is shown.
func showSetupInfo() error {
	c, _, err := loadConfig([]string{"-config", installConfig}, false)
	if err != nil {
		return err
	}
	for range 30 {
		if fileExists(filepath.Join(c.DataDir, "webdavgo.db")) && fileExists(filepath.Join(c.CertDir, adminCertFile)) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println()
	deadline := time.Now().Add(schemaWait)
	announced := false
	for {
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(installBin, "setup-info", "-config", installConfig)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err != nil && bytes.Contains(stdout.Bytes(), []byte(schemaPendingHint)) && time.Now().Before(deadline) {
			if !announced {
				fmt.Println("Waiting for the service to migrate the database ...")
				announced = true
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		os.Stdout.Write(stdout.Bytes())
		os.Stderr.Write(stderr.Bytes())
		if err != nil {
			return fmt.Errorf("setup-info (check: journalctl -u %s): %w", serviceName, err)
		}
		return nil
	}
}

func runUninstall(args []string) int {
	fset := flag.NewFlagSet("webdavgo uninstall", flag.ContinueOnError)
	root := fset.String("root", "/", "prefix for every path; other than / skips systemctl and user removal")
	purge := fset.Bool("purge", false, "also remove "+installEtc+", "+installData+", "+installLogs+" and the system user")
	yes := fset.Bool("yes", false, "with -purge: do not ask for confirmation")
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if fset.NArg() > 0 {
		logger.Error("usage: webdavgo uninstall [-root dir] [-purge [-yes]]")
		return 2
	}
	system := filepath.Clean(*root) == "/"
	if system && !systemChecks("uninstall") {
		return 1
	}
	at := func(p string) string { return filepath.Join(*root, p) }

	var steps []planStep
	if system {
		steps = append(steps, planStep{
			desc: "systemctl disable --now " + serviceName,
			do: func() error {
				// Not installed is fine: uninstall must be repeatable.
				if exec.Command("systemctl", "cat", serviceName).Run() != nil {
					return nil
				}
				return systemctl("disable", "--now", serviceName)
			},
		})
	} else {
		steps = append(steps, planStep{desc: "skip systemctl (-root)"})
	}
	steps = append(steps, removeStep(at(installUnit), false), removeStep(at(installLogrotate), false))
	if system {
		steps = append(steps, planStep{desc: "systemctl daemon-reload", do: func() error { return systemctl("daemon-reload") }})
	}
	steps = append(steps, removeStep(at(installBin), false))
	if *purge {
		steps = append(steps,
			removeStep(at(installEtc), true),
			removeStep(at(installData), true),
			removeStep(at(installLogs), true),
		)
		if system {
			steps = append(steps, planStep{
				desc: "remove the system user and group " + serviceUser,
				do:   removeServiceUser,
			})
		}
	} else {
		steps = append(steps, planStep{desc: "keep " + at(installEtc) + " (configuration), " + at(installData) +
			" (database, user files, certificates) and " + at(installLogs) + " (logs); remove them with -purge"})
	}

	var confirm func() bool
	if *purge && !*yes {
		confirm = confirmPurge
	}
	code := runPlan("webdavgo uninstall will:", steps, confirm)
	if code == 0 && !*purge {
		// The log directory exists only once the service has started.
		if fileExists(at(installLogs)) {
			fmt.Printf("Kept: %s, %s and %s\n", at(installEtc), at(installData), at(installLogs))
		} else {
			fmt.Printf("Kept: %s and %s\n", at(installEtc), at(installData))
		}
	}
	return code
}

// confirmPurge asks for the hostname, so that a purge copied from a
// how-to into the wrong terminal does not delete data.
func confirmPurge() bool {
	host, _ := os.Hostname()
	fmt.Printf("-purge deletes the configuration, the logs and ALL data (database, user files, certificates).\nType the hostname (%s) to confirm: ", host)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return host != "" && strings.TrimSpace(line) == host
}

func removeStep(path string, tree bool) planStep {
	if _, err := os.Lstat(path); err != nil {
		return planStep{desc: "skip " + path + " (not present)"}
	}
	desc := "remove " + path
	if tree {
		desc += " and everything in it"
	}
	return planStep{desc: desc, do: func() error {
		var err error
		if tree {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}}
}

func removeServiceUser() error {
	if _, err := user.Lookup(serviceUser); err == nil {
		if out, err := exec.Command("userdel", serviceUser).CombinedOutput(); err != nil {
			return fmt.Errorf("userdel: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	// userdel removes a group of the same name only on some distributions.
	if _, err := user.LookupGroup(serviceUser); err == nil {
		if out, err := exec.Command("groupdel", serviceUser).CombinedOutput(); err != nil {
			return fmt.Errorf("groupdel: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	return nil
}

// reexecAsServiceUser runs the current command (setup-info, reset-totp)
// again as the webdavgo system user when it was started as root on Linux.
// SQLite creates the -wal and -shm files next to the database as whoever
// opens it first; root-owned ones would lock the service out of its own
// database. done is false when the command should simply go on in this
// process.
func reexecAsServiceUser() (code int, done bool) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return 0, false
	}
	u, err := user.Lookup(serviceUser)
	if err != nil {
		return 0, false
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	exe, err := os.Executable()
	if err != nil {
		logger.Error("cannot locate the running binary", "err", err)
		return 1, true
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true
		}
		logger.Error("cannot run as user "+serviceUser, "err", err)
		return 1, true
	}
	return 0, true
}

// ---- file helpers ------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// sameContent reports whether a and b exist and have the same bytes.
func sameContent(a, b string) (bool, error) {
	ha, err := fileHash(a)
	if err != nil {
		return false, err
	}
	hb, err := fileHash(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func fileHash(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// copyAtomic copies src to dst through a temporary file in dst's directory
// and a rename, so a running service never sees a half-written binary and
// an update can replace the binary of the running process.
func copyAtomic(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	return writeAtomicFrom(dst, in, mode)
}

func writeAtomic(dst string, data []byte, mode os.FileMode) error {
	return writeAtomicFrom(dst, bytes.NewReader(data), mode)
}

func writeAtomicFrom(dst string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(dst), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".webdavgo-install-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", dst, err)
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("rename to %s: %w", dst, err)
	}
	return nil
}
