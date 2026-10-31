// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// config.go – process configuration from webdavgo.conf and flags. The
// file holds every setting, including those the admin UI changes (listener
// addresses, TLS); the database holds runtime data only (users, shares,
// quota counters, setup token, session epochs).

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the effective process configuration.
type Config struct {
	DataDir               string        `toml:"data_dir"`
	LogLevel              string        `toml:"log_level"`
	AuthCacheTTL          time.Duration `toml:"auth_cache_ttl"`
	ShutdownTimeout       time.Duration `toml:"shutdown_timeout"`
	ReadHeaderTimeout     time.Duration `toml:"read_header_timeout"`
	IdleTimeout           time.Duration `toml:"idle_timeout"`
	MaxRequestBody        int64         `toml:"max_request_body"`
	AllowPropfindInfinity bool          `toml:"allow_propfind_infinity"`
	MaxConnections        int           `toml:"max_connections"`
	MaxConnectionsPerIP   int           `toml:"max_connections_per_ip"`

	HTTP2MaxConcurrentStreams int `toml:"http2_max_concurrent_streams"`

	// UnauthRate and UnauthBurst are the token bucket per client for WebDAV
	// requests without credentials: tokens per second and bucket size.
	UnauthRate  int `toml:"unauth_rate"`
	UnauthBurst int `toml:"unauth_burst"`

	TLSMode     string `toml:"tls_mode"`
	RequireTLS  bool   `toml:"require_tls"`
	Domain      string `toml:"domain"`
	ACMEEmail   string `toml:"acme_email"`
	ACMECA      string `toml:"acme_ca"`
	ACMETrialCA string `toml:"acme_trial_ca"`
	ACMECARoot  string `toml:"acme_ca_root"`
	CertDir     string `toml:"cert_dir"`

	BruteforceWindow           time.Duration `toml:"bruteforce_window"`
	BruteforceIPThreshold      int           `toml:"bruteforce_ip_threshold"`
	BruteforceLockoutBase      time.Duration `toml:"bruteforce_lockout_base"`
	BruteforceLockoutMax       time.Duration `toml:"bruteforce_lockout_max"`
	BruteforceAccountThreshold int           `toml:"bruteforce_account_threshold"`
	BruteforceAccountInterval  time.Duration `toml:"bruteforce_account_interval"`
	BruteforceMaxEntries       int           `toml:"bruteforce_max_entries"`

	BodyReadIdleTimeout time.Duration `toml:"body_read_idle_timeout"`
	BodyMinRate         int64         `toml:"body_min_rate"`
	BodyMinRateGrace    time.Duration `toml:"body_min_rate_grace"`

	ResponseWriteIdleTimeout time.Duration `toml:"response_write_idle_timeout"`
	ResponseMinRate          int64         `toml:"response_min_rate"`
	ResponseMinRateGrace     time.Duration `toml:"response_min_rate_grace"`

	// The listeners as bound at startup: a port and a host or IP literal,
	// "" for all interfaces. The domain wizard moves WebDAVPort to 443. The
	// Settings page
	// writes new values to the file, which take effect on the next start.
	WebDAVPort          int    `toml:"webdav_port"`
	WebDAVListenAddress string `toml:"webdav_listen_address"`
	WebGUIPort          int    `toml:"webgui_port"`
	WebGUIListenAddress string `toml:"webgui_listen_address"`

	// The health listener: plain HTTP without authentication, /livez and
	// /readyz only, for container runtimes, load balancers and
	// "webdavgo healthcheck".
	HealthEnabled bool   `toml:"health_enabled"`
	HealthBind    string `toml:"health_bind"`
	HealthPort    int    `toml:"health_port"`

	// LogBufferEntries is the size of the in-memory log the admin UI shows.
	LogBufferEntries int `toml:"log_buffer_entries"`

	// DefaultQuota is the storage quota of a new user in bytes, 0 for
	// unlimited; GB in the file. Existing users keep theirs.
	DefaultQuota int64 `toml:"default_quota"`

	// MaxDeadPropsSize is the largest total size of the dead properties of one
	// resource in bytes, 0 for unlimited; KB in the file.
	MaxDeadPropsSize int64 `toml:"max_dead_props_size"`

	// AccessLog receives the "request" records and ServerLog every other
	// record; empty means stdout (a development run). Only the service opens
	// them.
	AccessLog string `toml:"access_log"`
	ServerLog string `toml:"server_log"`

	// ConfigFile is where the configuration lives and the admin UI saves.
	// ConfigRead is the file actually read: the old config.toml until
	// migrateConfigFile has replaced it, else ConfigFile.
	ConfigFile string `toml:"-"`
	ConfigRead string `toml:"-"`
	// Overrides maps the keys a command-line flag set to the flag's name;
	// the flag beats the file.
	Overrides map[string]string `toml:"-"`
}

// The running configuration. main sets it before any listener opens; Apply
// on the Settings page and the domain wizard replace it later, so readers
// take conf() at the point of use and never keep a field across requests.
// A Config is never modified once stored: writers copy it under cfgMu,
// change the copy and store that (setConf).
var (
	cfgPtr atomic.Pointer[Config]
	cfgMu  sync.Mutex
)

func init() { cfgPtr.Store(&Config{}) }

// conf returns the running configuration; the caller must not modify it.
func conf() *Config { return cfgPtr.Load() }

// setConf makes c the running configuration.
func setConf(c Config) { cfgPtr.Store(&c) }

const (
	// defaultConfigFile is used without -config (Linux convention).
	defaultConfigFile = "/etc/webdavgo/webdavgo.conf"
	confFileName      = "webdavgo.conf"
	// oldConfigFileName is the file's name from before it held every
	// setting; a webdavgo.conf next to it replaces it (migrateConfigFile).
	oldConfigFileName = "config.toml"

	defaultWebDAVPort = 8080
	defaultWebGUIPort = 8443
	defaultHealthPort = 8082
	defaultAccessLog  = "/var/log/webdavgo/access.log"
	defaultServerLog  = "/var/log/webdavgo/webdavgo.log"
)

// currentConfig returns a copy of the running configuration that the
// caller may modify.
func currentConfig() Config { return *conf() }

func defaultConfig() Config {
	return Config{
		DataDir:           "./data",
		LogLevel:          "info",
		AuthCacheTTL:      5 * time.Minute,
		ShutdownTimeout:   30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxRequestBody:    1_000_000,
		MaxConnections:    256,
		// One client must not be able to take all max_connections slots;
		// 32 is far above what a WebDAV client opens (HTTP/2 multiplexes).
		MaxConnectionsPerIP: 32,
		// The busiest legitimate client seen sent 30 req/s, all of them
		// authenticated; a client without credentials needs only a few
		// requests before it sends them.
		UnauthRate:  20,
		UnauthBurst: 50,
		// Go's default is 250 streams per HTTP/2 connection, which would turn
		// max_connections into a limit of 64 000 concurrent requests.
		HTTP2MaxConcurrentStreams: 32,
		LogBufferEntries:          2000,
		DefaultQuota:              1_000_000_000,
		WebDAVPort:                defaultWebDAVPort,
		WebGUIPort:                defaultWebGUIPort,
		HealthEnabled:             false,
		HealthBind:                "127.0.0.1",
		HealthPort:                defaultHealthPort,
		AccessLog:                 defaultAccessLog,
		ServerLog:                 defaultServerLog,

		TLSMode: "off",
		ACMECA:  "production",

		BruteforceWindow:           15 * time.Minute,
		BruteforceIPThreshold:      10,
		BruteforceLockoutBase:      time.Minute,
		BruteforceLockoutMax:       time.Hour,
		BruteforceAccountThreshold: 20,
		BruteforceAccountInterval:  5 * time.Second,
		BruteforceMaxEntries:       100000,

		BodyReadIdleTimeout: 30 * time.Second,
		BodyMinRate:         1000,
		BodyMinRateGrace:    60 * time.Second,

		ResponseWriteIdleTimeout: 30 * time.Second,
		ResponseMinRate:          1000,
		ResponseMinRateGrace:     60 * time.Second,
	}
}

// loadConfig parses args (without the program name) and returns the
// effective configuration and the arguments left after the flags.
// Precedence is flag > config file > default. create is set for the
// service: a missing config file is created from the defaults first
// (createConfigFile), and old-format values in it are converted in place
// (upgradeConfigFile). The CLI commands do neither, so that a command run
// as root never leaves a root-owned file behind and the file is converted
// only at service startup. The TLS keys are validated separately,
// in validateTLS, once migrateStoredSettings may have added them to the
// file.
func loadConfig(args []string, create bool) (Config, []string, error) {
	fset := flag.NewFlagSet("webdavgo", flag.ContinueOnError)
	configPath := fset.String("config", "", "config file (default "+defaultConfigFile+"; created from the defaults if missing)")
	dataDir := fset.String("data-dir", "", "data directory (overrides data_dir)")
	logLevel := fset.String("log-level", "", "debug|info|warn|error (overrides log_level)")
	if err := fset.Parse(args); err != nil {
		return Config{}, nil, err
	}

	c := defaultConfig()
	path, old := configPaths(*configPath)
	c.ConfigFile = path
	for _, p := range []string{path, old} {
		if p == "" {
			continue
		}
		_, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		// Anything else, e.g. no permission on /etc/webdavgo, must not be
		// taken for a missing file.
		if err != nil {
			return Config{}, nil, fmt.Errorf("read config %s: %w", p, err)
		}
		if p == path && create {
			// Only the service converts old-format values in the file,
			// at its start.
			if err := upgradeConfigFile(p); err != nil {
				return Config{}, nil, err
			}
			if err := readConfigFile(p, &c); err != nil {
				return Config{}, nil, err
			}
		} else {
			// The CLI commands never write the file, and the old
			// config.toml is never written: both are upgraded in memory
			// here (config.toml again when migrateConfigFile copies it).
			data, err := os.ReadFile(p)
			if err != nil {
				return Config{}, nil, fmt.Errorf("read config %s: %w", p, err)
			}
			text, _, err := upgradeConfigText(string(data))
			if err != nil {
				return Config{}, nil, fmt.Errorf("config %s: %w", p, err)
			}
			if err := decodeConfigText(p, text, &c); err != nil {
				return Config{}, nil, err
			}
		}
		c.ConfigRead = p
		break
	}
	if c.ConfigRead == "" {
		if !create {
			return Config{}, nil, fmt.Errorf("read config %s: %w", path, fs.ErrNotExist)
		}
		if err := createConfigFile(path); err != nil {
			return Config{}, nil, err
		}
		logger.Info("config file created with the default values", "path", path)
		if err := readConfigFile(path, &c); err != nil {
			return Config{}, nil, err
		}
		c.ConfigRead = path
	}

	fset.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "data-dir":
			c.DataDir = *dataDir
			c.Overrides = setOverride(c.Overrides, "data_dir", "-data-dir")
		case "log-level":
			c.LogLevel = *logLevel
			c.Overrides = setOverride(c.Overrides, "log_level", "-log-level")
		}
	})
	c.resolve()

	if err := c.validate(); err != nil {
		return Config{}, nil, err
	}
	return c, fset.Args(), nil
}

// configPaths returns the config file for the -config value and the old
// config.toml it replaces, if any. A -config naming a config.toml, as the
// ExecStart of units written by older versions does, means the
// webdavgo.conf in the same directory.
func configPaths(flagPath string) (path, old string) {
	if flagPath == "" {
		flagPath = filepath.Join(filepath.Dir(defaultConfigFile), oldConfigFileName)
	}
	if filepath.Base(flagPath) == oldConfigFileName {
		return filepath.Join(filepath.Dir(flagPath), confFileName), flagPath
	}
	return flagPath, ""
}

// containerMode is set by the container image (WEBDAVGO_CONTAINER=1). It
// only selects the text createConfigFile writes.
var containerMode = os.Getenv("WEBDAVGO_CONTAINER") == "1"

// containerConfigText is the example as a new container needs it: the
// health listener for the image's HEALTHCHECK, and both logs on stdout so
// that docker logs shows them.
var containerConfigText = setConfLines(exampleConfigText, map[string]string{
	"health_enabled": "true",
	"access_log":     tomlString(""),
	"server_log":     tomlString(""),
})

// createConfigFile writes webdavgo.example.conf, every key with its
// default and description, to path, and creates its directory if missing.
// In a container it writes containerConfigText instead.
func createConfigFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("cannot create config directory %s: %w", dir, err)
	}
	text := exampleConfigText
	if containerMode {
		text = containerConfigText
	}
	if err := replaceFile(path, []byte(text), nil); err != nil {
		return fmt.Errorf("cannot create config file %s: %w", path, err)
	}
	return nil
}

// readConfigFile decodes the file at path over c.
func readConfigFile(path string, c *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	return decodeConfigText(path, string(data), c)
}

// decodeConfigText decodes text, the content of the file name, over c. It
// does not decode into the struct: a duration is whole seconds in the file
// but a time.Duration in c, a size KB in the file but bytes in c, and only
// setFileValue knows the units.
func decodeConfigText(name, text string, c *Config) error {
	var m map[string]any
	if _, err := toml.Decode(text, &m); err != nil {
		return fmt.Errorf("read config %s: %w", name, err)
	}
	// A misspelt key would otherwise silently fall back to its default,
	// which for limits and timeouts is easy to miss in production.
	var unknown []string
	for _, key := range slices.Sorted(maps.Keys(m)) {
		if _, ok := configKeys[key]; !ok {
			unknown = append(unknown, key)
			continue
		}
		if err := setFileValue(c, key, m[key]); err != nil {
			return fmt.Errorf("config %s: %w", name, err)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("config %s: unknown key(s): %s", name, strings.Join(unknown, ", "))
	}
	return nil
}

// byteUnits are the sizes and rates the file gives in a decimal unit of
// bytes (1 KB = 1000 bytes, 1 GB = 10^9 bytes). c holds them in bytes.
var byteUnits = map[string]struct {
	unit   string
	factor int64
}{
	"max_request_body":    {"KB", 1000},
	"body_min_rate":       {"KB/s", 1000},
	"response_min_rate":   {"KB/s", 1000},
	"default_quota":       {"GB", 1_000_000_000},
	"max_dead_props_size": {"KB", 1000},
}

// countUnits name the unit of a count that is stored as it is.
var countUnits = map[string]string{"unauth_rate": "requests/s"}

// configUnit names the unit of key in the file and on the Settings page,
// or "" for a unitless value.
func configUnit(key string) string {
	if u, ok := byteUnits[key]; ok {
		return u.unit
	}
	if u, ok := countUnits[key]; ok {
		return u
	}
	if _, ok := configValue(&Config{}, key).Interface().(time.Duration); ok {
		return "seconds"
	}
	return ""
}

// fileValue returns key of c as the file holds it: durations as whole
// seconds, byteUnits in their unit, integers as int64, strings and booleans as they
// are. saveConfig takes these values.
func fileValue(c *Config, key string) any {
	switch v := configValue(c, key).Interface().(type) {
	case time.Duration:
		return int64(v / time.Second)
	case int:
		return int64(v)
	case int64:
		if u, ok := byteUnits[key]; ok {
			return v / u.factor
		}
		return v
	default:
		return v
	}
}

// setFileValue sets key of c from v as the TOML decoder returns it. A value
// of another type, such as an old "30s" for a duration, is an error naming
// the key.
func setFileValue(c *Config, key string, v any) error {
	f := configValue(c, key)
	switch f.Interface().(type) {
	case string:
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s = %v: must be a string", key, v)
		}
		f.SetString(s)
	case bool:
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("%s = %v: must be true or false", key, v)
		}
		f.SetBool(b)
	case time.Duration:
		n, ok := v.(int64)
		if !ok {
			return fmt.Errorf("%s = %q: must be a whole number of seconds", key, fmt.Sprint(v))
		}
		if n > math.MaxInt64/int64(time.Second) || n < math.MinInt64/int64(time.Second) {
			return fmt.Errorf("%s = %d: too large", key, n)
		}
		f.SetInt(n * int64(time.Second))
	case int, int64:
		n, ok := v.(int64)
		if !ok {
			unit := configUnit(key)
			if unit == "" {
				unit = "a whole number"
			} else {
				unit = "a whole number of " + unit
			}
			return fmt.Errorf("%s = %q: must be %s", key, fmt.Sprint(v), unit)
		}
		if u, ok := byteUnits[key]; ok {
			if n > math.MaxInt64/u.factor || n < math.MinInt64/u.factor {
				return fmt.Errorf("%s = %d: too large", key, n)
			}
			n *= u.factor
		}
		f.SetInt(n)
	}
	return nil
}

// webdavAddr and webguiAddr are the listen strings of the listeners,
// [host]:port, as net.Listen takes them.
func (c Config) webdavAddr() string {
	return net.JoinHostPort(c.WebDAVListenAddress, strconv.Itoa(c.WebDAVPort))
}

func (c Config) webguiAddr() string {
	return net.JoinHostPort(c.WebGUIListenAddress, strconv.Itoa(c.WebGUIPort))
}

// ---- upgrade of the old value format --------------------------------------

// configChange is one value upgradeConfigText converted.
type configChange struct {
	key, old, new string
	rounded       bool // a duration that was not whole seconds, rounded up
}

// formatMarkerRE matches the line "# webdavgo config format 2: ..." that
// builds of the unit change before its release put on top of a converted
// file. Nothing reads it; upgradeConfigText removes it where found.
var formatMarkerRE = regexp.MustCompile(`(?m)^#[ \t]*webdavgo config format 2\b.*(\r?\n|$)`)

// markerChange is the configChange key for a removed format marker line.
const markerChange = "format marker line"

// oldAddrKeys map the old listener keys to their listen address and port.
var oldAddrKeys = [][3]string{
	{"webdav_addr", "webdav_listen_address", "webdav_port"},
	{"webgui_addr", "webgui_listen_address", "webgui_port"},
}

// upgradeConfigText rewrites the values of text that are in the format of
// older versions, line by line like setConfLines: webdav_addr and
// webgui_addr become a listen address and a port, duration strings whole
// seconds (rounded up). It runs on every read of webdavgo.conf, so such a
// value is converted whenever it appears. Plain integers are always taken in
// the current units and never converted. A format marker line from earlier
// builds is removed.
func upgradeConfigText(text string) (string, []configChange, error) {
	var changes []configChange
	if loc := formatMarkerRE.FindStringIndex(text); loc != nil {
		text = text[:loc[0]] + text[loc[1]:]
		changes = append(changes, configChange{key: markerChange})
	}
	var m map[string]any
	// A file that does not parse is reported by the strict read that
	// follows.
	if _, err := toml.Decode(text, &m); err != nil {
		return text, changes, nil
	}
	var durationKeys []string
	for _, key := range slices.Sorted(maps.Keys(configKeys)) {
		if configUnit(key) == "seconds" {
			durationKeys = append(durationKeys, key)
		}
	}

	lines := map[string]string{}
	for _, key := range durationKeys {
		s, ok := m[key].(string)
		if !ok {
			continue
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return text, nil, fmt.Errorf("%s = %q: cannot convert to seconds: %w", key, s, err)
		}
		secs := int64(d / time.Second)
		if d%time.Second > 0 {
			secs++
		}
		lines[key] = strconv.FormatInt(secs, 10)
		changes = append(changes, configChange{key, strconv.Quote(s), lines[key], d%time.Second != 0})
	}
	text = setConfLines(text, lines)

	for _, k := range oldAddrKeys {
		s, ok := m[k[0]].(string)
		if !ok {
			continue
		}
		host, portStr, err := net.SplitHostPort(s)
		port, perr := strconv.Atoi(portStr)
		if err != nil || perr != nil {
			return text, nil, fmt.Errorf("%s = %q: cannot split into listen address and port", k[0], s)
		}
		var repl []string
		// A file that already has the new keys keeps them; only the old
		// line goes.
		if _, has := m[k[1]]; !has {
			repl = append(repl, k[1]+" = "+tomlString(host))
		}
		if _, has := m[k[2]]; !has {
			repl = append(repl, k[2]+" = "+strconv.Itoa(port))
		}
		text = replaceConfLine(text, k[0], repl)
		changes = append(changes, configChange{key: k[0], old: strconv.Quote(s),
			new: fmt.Sprintf("%s = %q, %s = %d", k[1], host, k[2], port)})
	}
	return text, changes, nil
}

// replaceConfLine replaces the active line of key with lines (none deletes
// it), keeping its indentation and line ending.
func replaceConfLine(text, key string, lines []string) string {
	active := regexp.MustCompile(`^([ \t]*)` + regexp.QuoteMeta(key) + `[ \t]*=`)
	all := strings.SplitAfter(text, "\n")
	i := slices.IndexFunc(all, active.MatchString)
	if i < 0 {
		return text
	}
	indent := active.FindStringSubmatch(all[i])[1]
	eol := ""
	if strings.HasSuffix(all[i], "\r\n") {
		eol = "\r\n"
	} else if strings.HasSuffix(all[i], "\n") {
		eol = "\n"
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(indent + l + eol)
	}
	if b.Len() > 0 && eol == "" {
		// The last line of a file without a final newline.
		all[i] = strings.TrimSuffix(b.String(), eol)
	} else {
		all[i] = b.String()
	}
	return strings.Join(all, "")
}

// upgradeConfigFile converts old-format values of the config file at path
// in place (upgradeConfigText), keeping mode and owner, and logs each
// converted key.
func upgradeConfigFile(path string) error {
	confWriteMu.Lock()
	defer confWriteMu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	text, changes, err := upgradeConfigText(string(data))
	if err != nil {
		return fmt.Errorf("config %s: %w", path, err)
	}
	if len(changes) == 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := replaceFile(path, []byte(text), info); err != nil {
		return fmt.Errorf("upgrade config %s: %w", path, err)
	}
	logConfigChanges(path, changes)
	return nil
}

func logConfigChanges(path string, changes []configChange) {
	for _, ch := range changes {
		if ch.key == markerChange {
			logger.Info("config format marker line removed; it is no longer used", "path", path)
			continue
		}
		if ch.rounded {
			logger.Warn("config value converted to the new format; not whole seconds, rounded up",
				"key", ch.key, "old", ch.old, "new", ch.new, "path", path)
			continue
		}
		logger.Info("config value converted to the new format", "key", ch.key, "old", ch.old, "new", ch.new, "path", path)
	}
}

func setOverride(m map[string]string, key, flagName string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[key] = flagName
	return m
}

// resolve fills in what defaults to another key. It runs after the flags,
// so that -data-dir moves the certificates along with the rest of the data.
func (c *Config) resolve() {
	if c.CertDir == "" {
		c.CertDir = filepath.Join(c.DataDir, "certs")
	}
}

// fileConfig returns the defaults overlaid with the file at path as it is
// now, which may hold values saved since startup.
func fileConfig(path string) (Config, error) {
	c := defaultConfig()
	err := readConfigFile(path, &c)
	return c, err
}

// savedConfig is what the next start would run with: the file as it is now
// with the running process's flags on top.
func savedConfig() (Config, error) {
	run := conf()
	c, err := fileConfig(run.ConfigFile)
	if err != nil {
		return Config{}, err
	}
	for key := range run.Overrides {
		configValue(&c, key).Set(configValue(run, key))
	}
	c.ConfigFile, c.ConfigRead, c.Overrides = run.ConfigFile, run.ConfigRead, run.Overrides
	c.resolve()
	return c, nil
}

// configKeys maps every key of the file to the index of its Config field.
var configKeys = func() map[string]int {
	m := map[string]int{}
	t := reflect.TypeFor[Config]()
	for i := range t.NumField() {
		if key := t.Field(i).Tag.Get("toml"); key != "" && key != "-" {
			m[key] = i
		}
	}
	return m
}()

// configValue returns the field of c that holds key; key must be one of
// configKeys.
func configValue(c *Config, key string) reflect.Value {
	return reflect.ValueOf(c).Elem().Field(configKeys[key])
}

// migrateConfigFile creates path from old, byte for byte and with old's
// mode. The owner is the process's: the service user could not give the
// file root as owner, and must own it to save to it later. old is left as
// it is, so an older binary still finds it.
func migrateConfigFile(old, path string) error {
	raw, err := os.ReadFile(old)
	if err != nil {
		return fmt.Errorf("read %s: %w", old, err)
	}
	text, changes, err := upgradeConfigText(string(raw))
	if err != nil {
		return fmt.Errorf("config %s: %w", old, err)
	}
	data := []byte(text)
	info, err := os.Stat(old)
	if err != nil {
		return fmt.Errorf("stat %s: %w", old, err)
	}
	if err := replaceFile(path, data, nil); err != nil {
		return fmt.Errorf("create %s from %s: %w", path, old, err)
	}
	if err := os.Chmod(path, info.Mode().Perm()); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	logConfigChanges(path, changes)
	return nil
}

// confWriteMu serialises saveConfig, so that the Settings page and the
// domain wizard saving at the same time do not lose each other's lines.
var confWriteMu sync.Mutex

// saveConfig sets the keys of kv in the config file at path, line by line
// (setConfLines), and creates the file if it does not exist. A value is in
// the file's format, as fileValue returns it: a string, bool or integer
// (whole seconds for durations, byteUnits in their unit).
// Keys whose file value already equals it are not touched; if none
// changes, the file is not written at all.
func saveConfig(path string, kv map[string]any) error {
	confWriteMu.Lock()
	defer confWriteMu.Unlock()

	var data []byte
	info, err := os.Stat(path)
	switch {
	case err == nil:
		data, err = os.ReadFile(path)
	case errors.Is(err, fs.ErrNotExist):
		info, err = nil, nil
	}
	if err != nil {
		return fmt.Errorf("save config %s: %w", path, err)
	}
	var current map[string]any
	if _, err := toml.Decode(string(data), &current); err != nil {
		return fmt.Errorf("save config %s: the file does not parse: %w", path, err)
	}
	lines := map[string]string{}
	for k, v := range kv {
		if cur, ok := current[k]; ok && sameTOMLValue(cur, v) {
			continue
		}
		lit, err := tomlLiteral(v)
		if err != nil {
			return fmt.Errorf("save config %s: %s: %w", path, k, err)
		}
		lines[k] = lit
	}
	if len(lines) == 0 {
		return nil
	}
	out := setConfLines(string(data), lines)
	// A file the service would refuse at its next start must not be
	// written in the first place.
	c := defaultConfig()
	md, err := toml.Decode(out, &c)
	if err == nil && len(md.Undecoded()) > 0 {
		err = fmt.Errorf("unknown key(s): %v", md.Undecoded())
	}
	if err != nil {
		return fmt.Errorf("save config %s: result does not parse: %w", path, err)
	}
	if err := replaceFile(path, []byte(out), info); err != nil {
		return fmt.Errorf("save config %s: %w", path, err)
	}
	return nil
}

// setConfLines returns content with each key of kv set to its value, a
// TOML literal. Only one line per key is rewritten: the active
// "key = ..." line, else the first commented-out "#key = ..." line, which
// becomes active, else a new line appended at the end. Every other byte
// (comments, blank lines, order, an operator's edits) stays as it is.
func setConfLines(content string, kv map[string]string) string {
	lines := strings.SplitAfter(content, "\n")
	var appended strings.Builder
	for _, k := range slices.Sorted(maps.Keys(kv)) {
		active := regexp.MustCompile(`^([ \t]*)` + regexp.QuoteMeta(k) + `[ \t]*=`)
		commented := regexp.MustCompile(`^([ \t]*)#[ \t]*` + regexp.QuoteMeta(k) + `[ \t]*=`)
		i := slices.IndexFunc(lines, active.MatchString)
		re := active
		if i < 0 {
			i = slices.IndexFunc(lines, commented.MatchString)
			re = commented
		}
		if i < 0 {
			appended.WriteString(k + " = " + kv[k] + "\n")
			continue
		}
		indent := re.FindStringSubmatch(lines[i])[1]
		eol := ""
		if strings.HasSuffix(lines[i], "\r\n") {
			eol = "\r\n"
		} else if strings.HasSuffix(lines[i], "\n") {
			eol = "\n"
		}
		lines[i] = indent + k + " = " + kv[k] + eol
	}
	out := strings.Join(lines, "")
	if appended.Len() > 0 && out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out + appended.String()
}

// tomlLiteral renders v, a value as fileValue returns it, as a TOML literal.
func tomlLiteral(v any) (string, error) {
	switch v := v.(type) {
	case string:
		return tomlString(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	}
	return "", fmt.Errorf("unsupported type %T", v)
}

// sameTOMLValue reports whether cur, a value as the TOML decoder returns it
// into an untyped map, equals v, a value as fileValue returns it.
func sameTOMLValue(cur, v any) bool {
	switch v := v.(type) {
	case string:
		c, ok := cur.(string)
		return ok && c == v
	case bool:
		c, ok := cur.(bool)
		return ok && c == v
	case int:
		c, ok := cur.(int64)
		return ok && c == int64(v)
	case int64:
		c, ok := cur.(int64)
		return ok && c == v
	}
	return false
}

// tomlString renders s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// replaceFile writes data to path through a temporary file in the same
// directory and a rename, so that no reader ever sees half a file. The
// file gets the mode and owner of like (the file it replaces or is made
// from), or 0640 and the process's owner if like is nil. The directory
// must exist.
func replaceFile(path string, data []byte, like fs.FileInfo) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	mode := fs.FileMode(0640)
	if like != nil {
		mode = like.Mode().Perm()
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmp.Name(), err)
	}
	if like != nil {
		if err := chownLike(tmp, like); err != nil {
			tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}

// chownLike gives f the owner and group of like. It only calls chown when
// they differ, because a non-root process may not chown at all on some
// systems even to its own ids.
func chownLike(f *os.File, like fs.FileInfo) error {
	want, ok := like.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", f.Name(), err)
	}
	if have, ok := info.Sys().(*syscall.Stat_t); ok && have.Uid == want.Uid && have.Gid == want.Gid {
		return nil
	}
	if err := f.Chown(int(want.Uid), int(want.Gid)); err != nil {
		return fmt.Errorf("keep owner %d:%d: %w", want.Uid, want.Gid, err)
	}
	return nil
}

// fieldError is a configuration problem and the key it belongs to.
type fieldError struct {
	Key string
	Err error
}

// validate returns the first problem of the keys checked at startup
// before the database is opened; TLS comes later, in validateTLS.
func (c Config) validate() error {
	if errs := c.checkGeneral(); len(errs) > 0 {
		return errs[0].Err
	}
	return nil
}

// validateTLS checks the ACME keys only as far as possible without network
// access; whether the domain resolves to this host shows when CertMagic
// tries to obtain the certificate. It runs after migrateStoredSettings,
// which may move domain and tls_mode from an old database into the file.
func (c Config) validateTLS() error {
	if errs := c.checkTLS(); len(errs) > 0 {
		return errs[0].Err
	}
	return nil
}

// fieldErrors returns every problem of c, for the Settings page to show
// next to each field.
func (c Config) fieldErrors() []fieldError {
	errs := append(c.checkGeneral(), c.checkTLS()...)
	if normaliseAddr(c.webdavAddr()) == normaliseAddr(c.webguiAddr()) {
		errs = append(errs, fieldError{"webgui_port", errors.New("the WebDAV and the admin listener must not use the same address and port")})
	}
	// By port alone, not address: on the same port, a wildcard bind and a
	// specific one collide, and which one runs depends on the order.
	if c.HealthEnabled && (c.HealthPort == c.WebDAVPort || c.HealthPort == c.WebGUIPort) {
		errs = append(errs, fieldError{"health_port", errors.New("health_port must differ from webdav_port and webgui_port")})
	}
	return errs
}

func (c Config) checkGeneral() []fieldError {
	var errs []fieldError
	add := func(key, format string, a ...any) {
		errs = append(errs, fieldError{key, fmt.Errorf(format, a...)})
	}
	if c.DataDir == "" {
		add("data_dir", "data_dir must not be empty")
	}
	if _, err := parseLogLevel(c.LogLevel); err != nil {
		errs = append(errs, fieldError{"log_level", err})
	}
	if c.AuthCacheTTL < 0 {
		add("auth_cache_ttl", "auth_cache_ttl must not be negative")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"shutdown_timeout", c.ShutdownTimeout},
		{"read_header_timeout", c.ReadHeaderTimeout},
		{"idle_timeout", c.IdleTimeout},
	} {
		if d.v <= 0 {
			add(d.name, "%s must be positive", d.name)
		}
	}
	if c.MaxRequestBody <= 0 {
		add("max_request_body", "max_request_body must be positive")
	}
	for _, n := range []struct {
		name string
		v    int
	}{
		{"max_connections", c.MaxConnections},
		{"max_connections_per_ip", c.MaxConnectionsPerIP},
		{"unauth_rate", c.UnauthRate},
		{"unauth_burst", c.UnauthBurst},
		{"http2_max_concurrent_streams", c.HTTP2MaxConcurrentStreams},
		{"log_buffer_entries", c.LogBufferEntries},
	} {
		if n.v <= 0 {
			add(n.name, "%s must be positive", n.name)
		}
	}
	// The service runs with / as working directory; a relative path would
	// depend on wherever it was started from.
	for _, p := range []struct{ name, v string }{{"access_log", c.AccessLog}, {"server_log", c.ServerLog}} {
		if p.v != "" && !filepath.IsAbs(p.v) {
			add(p.name, "%s %q: must be an absolute path", p.name, p.v)
		}
	}
	for _, p := range []struct {
		name string
		v    int
	}{{"webdav_port", c.WebDAVPort}, {"webgui_port", c.WebGUIPort}, {"health_port", c.HealthPort}} {
		if p.v < 1 || p.v > 65535 {
			add(p.name, "%s %d: must be between 1 and 65535", p.name, p.v)
		}
	}
	for _, a := range []struct{ name, v string }{{"webdav_listen_address", c.WebDAVListenAddress}, {"webgui_listen_address", c.WebGUIListenAddress}, {"health_bind", c.HealthBind}} {
		if !validListenAddress(a.v) {
			add(a.name, "%s %q: must be empty (all interfaces) or a host name or IP address, without port", a.name, a.v)
		}
	}
	if c.DefaultQuota < 0 || c.DefaultQuota > maxQuotaGB*1_000_000_000 {
		add("default_quota", "default_quota must be between 0 (unlimited) and %d GB", maxQuotaGB)
	}
	if c.MaxDeadPropsSize < 0 {
		add("max_dead_props_size", "max_dead_props_size must not be negative")
	}
	if c.BruteforceMaxEntries <= 0 {
		add("bruteforce_max_entries", "bruteforce_max_entries must be positive")
	}
	if c.ResponseMinRate < 0 {
		add("response_min_rate", "response_min_rate must not be negative")
	}
	if c.ResponseMinRateGrace < 0 {
		add("response_min_rate_grace", "response_min_rate_grace must not be negative")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"bruteforce_window", c.BruteforceWindow},
		{"bruteforce_lockout_base", c.BruteforceLockoutBase},
		{"bruteforce_lockout_max", c.BruteforceLockoutMax},
		{"bruteforce_account_interval", c.BruteforceAccountInterval},
		{"body_read_idle_timeout", c.BodyReadIdleTimeout},
		{"response_write_idle_timeout", c.ResponseWriteIdleTimeout},
	} {
		if d.v <= 0 {
			add(d.name, "%s must be positive", d.name)
		}
	}
	if c.BruteforceIPThreshold <= 0 {
		add("bruteforce_ip_threshold", "bruteforce_ip_threshold must be positive")
	}
	if c.BruteforceAccountThreshold <= 0 {
		add("bruteforce_account_threshold", "bruteforce_account_threshold must be positive")
	}
	if c.BruteforceLockoutMax < c.BruteforceLockoutBase {
		add("bruteforce_lockout_max", "bruteforce_lockout_max must not be less than bruteforce_lockout_base")
	}
	if c.BodyMinRate < 0 {
		add("body_min_rate", "body_min_rate must not be negative")
	}
	if c.BodyMinRateGrace < 0 {
		add("body_min_rate_grace", "body_min_rate_grace must not be negative")
	}
	return errs
}

func (c Config) checkTLS() []fieldError {
	var errs []fieldError
	add := func(key, format string, a ...any) {
		errs = append(errs, fieldError{key, fmt.Errorf(format, a...)})
	}
	switch c.ACMETrialCA {
	case "", "none", "staging":
	default:
		if !isHTTPSURL(c.ACMETrialCA) {
			add("acme_trial_ca", "acme_trial_ca %q: must be empty, none, staging or an https:// ACME directory URL", c.ACMETrialCA)
		}
	}
	switch c.TLSMode {
	case "off":
		return errs
	case "acme":
	default:
		add("tls_mode", "tls_mode %q: must be off or acme", c.TLSMode)
		return errs
	}
	if c.Domain == "" {
		add("domain", `domain is required when tls_mode = "acme"`)
	} else if !isPublicHostname(c.Domain) {
		add("domain", "domain %q: must be a public DNS name without wildcard, scheme or port", c.Domain)
	}
	switch c.ACMECA {
	case "production", "staging":
	default:
		if !isHTTPSURL(c.ACMECA) {
			add("acme_ca", "acme_ca %q: must be production, staging or an https:// ACME directory URL", c.ACMECA)
		}
	}
	if c.CertDir == "" {
		add("cert_dir", "cert_dir must not be empty")
	}
	return errs
}

func isHTTPSURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// trialCA returns the CA for the trial order the domain wizard places
// before the real one, or "" for none. By default only a production order
// gets a trial against Let's Encrypt staging: staging has far higher rate
// limits, so a mistake in DNS or port forwarding costs nothing there. A
// custom CA gets no trial unless acme_trial_ca names one.
func (c Config) trialCA() string {
	switch c.ACMETrialCA {
	case "none":
		return ""
	case "":
		if c.ACMECA == "production" {
			return "staging"
		}
		return ""
	}
	return c.ACMETrialCA
}

// hostnameLabelRE matches one DNS label (RFC 1123).
var hostnameLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// isPublicHostname reports whether name can get a certificate from a public
// CA: at least two labels, no IP address, no name that only resolves inside
// a LAN. Catching these at startup beats a failed ACME order much later.
func isPublicHostname(name string) bool {
	name = strings.ToLower(name)
	if len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !hostnameLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log_level %q: must be debug, info, warn or error", s)
}

// logAttrs returns the configuration as key-value pairs for the startup line.
func (c Config) logAttrs() []any {
	return []any{
		"data_dir", c.DataDir,
		"log_level", c.LogLevel,
		"auth_cache_ttl", c.AuthCacheTTL.String(),
		"shutdown_timeout", c.ShutdownTimeout.String(),
		"read_header_timeout", c.ReadHeaderTimeout.String(),
		"idle_timeout", c.IdleTimeout.String(),
		"max_request_body", c.MaxRequestBody,
		"allow_propfind_infinity", c.AllowPropfindInfinity,
		"max_connections", c.MaxConnections,
		"max_connections_per_ip", c.MaxConnectionsPerIP,
		"http2_max_concurrent_streams", c.HTTP2MaxConcurrentStreams,
		"unauth_rate", c.UnauthRate,
		"unauth_burst", c.UnauthBurst,
		"log_buffer_entries", c.LogBufferEntries,
		"health_enabled", c.HealthEnabled,
		"health_bind", c.HealthBind,
		"health_port", c.HealthPort,
		"default_quota", c.DefaultQuota,
		"max_dead_props_size", c.MaxDeadPropsSize,
		"access_log", c.AccessLog,
		"server_log", c.ServerLog,
		"tls_mode", c.TLSMode,
		"require_tls", c.RequireTLS,
		"domain", c.Domain,
		"acme_email", c.ACMEEmail,
		"acme_ca", c.ACMECA,
		"acme_trial_ca", c.ACMETrialCA,
		"acme_ca_root", c.ACMECARoot,
		"cert_dir", c.CertDir,
		"bruteforce_window", c.BruteforceWindow.String(),
		"bruteforce_ip_threshold", c.BruteforceIPThreshold,
		"bruteforce_lockout_base", c.BruteforceLockoutBase.String(),
		"bruteforce_lockout_max", c.BruteforceLockoutMax.String(),
		"bruteforce_account_threshold", c.BruteforceAccountThreshold,
		"bruteforce_account_interval", c.BruteforceAccountInterval.String(),
		"bruteforce_max_entries", c.BruteforceMaxEntries,
		"body_read_idle_timeout", c.BodyReadIdleTimeout.String(),
		"body_min_rate", c.BodyMinRate,
		"body_min_rate_grace", c.BodyMinRateGrace.String(),
		"response_write_idle_timeout", c.ResponseWriteIdleTimeout.String(),
		"response_min_rate", c.ResponseMinRate,
		"response_min_rate_grace", c.ResponseMinRateGrace.String(),
	}
}
