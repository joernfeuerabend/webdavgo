# webdavgo

webdavgo is a WebDAV file server in a single Go binary. It supports
WebDAV SEARCH (RFC 5323) and includes what is needed to run it directly
on the internet.

## Why

- **One function:** webdavgo serves files over WebDAV. It has no calendar,
  contacts, office, media or plugin features.
- **One binary:** Pure Go with embedded SQLite. No database server, no
  reverse proxy, no other runtime dependencies.
- **Easy to deploy:** Copy the binary to a Linux server, start it and
  finish the setup in the browser.
- **Internet-ready:** The server obtains and renews its TLS certificates
  from Let's Encrypt itself. Brute-force protection and request limits
  are built in.
- **SEARCH:** A client gets all files changed since a given time with a
  single request (`getlastmodified > T`) instead of walking the directory
  tree with PROPFIND. This also works inside shares.

## Screenshots

![Admin dashboard](docs/screenshots/dashboard.png)
![Status page](docs/screenshots/status.png)

## Features

**WebDAV & sync**
- WebDAV SEARCH (RFC 5323) with the basicsearch grammar: `and`, `or`,
  `not`, comparisons, `like`, `contains`, `orderby` and `limit`
- Conditional requests (`If-Match`, `If-None-Match`), atomic PUT and
  consistent ETags
- Standard WebDAV without client-specific extensions

**Users & sharing**
- Multiple users, each with an isolated data directory and a storage quota
- Invite external recipients to a folder by email, without creating an
  account for them. Invites are created through a REST API
  (`/api/v1/shares`), the only part of webdavgo outside the WebDAV
  standard; recipients then use plain WebDAV, including SEARCH

**Security features**
- Automatic TLS certificates via Let's Encrypt (ACME)
- Brute-force protection on all login paths
- Limits on slow request bodies
- Admin UI over HTTPS only, with TOTP two-factor authentication and
  CSRF protection

**Operation**
- First-run setup wizard with a one-time token and terminal QR code
- `webdavgo install` sets the server up as a system service
- Web admin UI for users, shares, connections, activity and a live log
- Files are stored as plain files in the data directory and can be backed
  up with standard tools

## Not included

CalDAV/CardDAV, office integration, media galleries, plugin system.

## Build

```sh
go build -o webdavgo      # or: make build
make dist                 # static binaries for linux/amd64, linux/arm64 in dist/
make test                 # go vet, then test.sh
make clean
```

`make` stamps the version from `git describe` into the binary
(`-ldflags "-X main.version=…"`); it is logged in the `startup` line. A plain
`go build` reports `dev`. `make dist` builds with `CGO_ENABLED=0`, `-trimpath`
and `-s -w`.

Requires Go 1.26 or later (see `go.mod`). Dependencies: `golang.org/x/net`
(webdav, netutil), `golang.org/x/crypto` (bcrypt), `modernc.org/sqlite`
(pure-Go SQLite), `github.com/mdp/qrterminal/v3`, `github.com/BurntSushi/toml`,
`github.com/caddyserver/certmagic` (ACME), `rsc.io/qr` (TOTP QR code as PNG).

## Run

```sh
./webdavgo                               # /etc/webdavgo/webdavgo.conf, created with the defaults if missing
./webdavgo -config ./webdavgo.conf       # likewise created if missing
```

On first start, the console prints:

```
SETUP REQUIRED
The admin UI is listening on all interfaces (port 8443) – reachable from any network that can reach port 8443.
Open one of these URLs in a browser:
  https://192.168.1.20:8443/setup?token=<hex>
  https://[fd00::20]:8443/setup?token=<hex>
  https://localhost:8443/setup?token=<hex>
<QR code for the first LAN IPv4 URL>
Admin certificate SHA-256 fingerprint: 83:27:50:…:AC:49
The browser will warn that the certificate is self-signed; continue only if it shows this fingerprint.
Token expires at <time>
```

There is one URL per LAN address of the host (IPv4 first), plus `localhost`;
the QR code is meant for a phone on the same network. The second line names
the address the admin listener is actually bound to (see
[Admin access](#admin-access)); webdavgo cannot see a firewall or router in
front of the host, so it never claims that the port is private. Open a URL, accept the
self-signed certificate after comparing its fingerprint (see
[Admin access](#admin-access)), and create the admin account. Setup then
continues directly with the TOTP enrolment for that account; it is complete,
and WebDAV starts serving (503 until then), once a first code is confirmed and
the recovery codes have been shown. No restart is needed.

The token is stored in the database and survives a restart; `webdavgo
setup-info` prints the URLs again (with a new token once the old one has
expired).

On subsequent starts the setup wizard is skipped — the admin account already
exists in the database.

## Configuration

All configuration lives in one file, `webdavgo.conf`: flat `key = value`
lines (TOML syntax), `#` starts a comment. Without `-config`, webdavgo reads
`/etc/webdavgo/webdavgo.conf`. If that file, or the one given with
`-config`, does not exist, the server creates it (and its directory) from
[`webdavgo.example.conf`](webdavgo.example.conf), i.e. with the default
values below, logs that at Info, and reads it. If it cannot be created, the
server exits with an error naming the path and the reason. `setup-info` and
`reset-totp` never create it: they need the service's file. Every key is
optional. The database holds runtime data only (users,
shares, quota counters, setup token, session epochs), no configuration.

| Flag | Meaning |
|------|---------|
| `-config <path>` | config file to read and save to (default `/etc/webdavgo/webdavgo.conf`) |
| `-data-dir <dir>` | overrides `data_dir` |
| `-log-level <level>` | overrides `log_level` |

Subcommands: `install`, `uninstall` (see [Deployment](#deployment-with-webdavgo-install)),
`setup-info` and `reset-totp` (see [Admin access](#admin-access)).

Precedence: **flag > config file > default.** The admin UI's **Settings**
page edits every key of the same file (see [Settings page](#settings-page));
the certificate request also writes `webdav_port = 443`. A save rewrites only the line of each changed key; if a key
has no active line but a commented-out `#key = ...` line, that line is
activated, otherwise `key = value` is appended at the end. Comments, blank
lines, order and your own edits stay as they are. The file is written
atomically (temporary file in the same directory, then rename) and keeps its
mode and owner; there are no backup files. If it cannot be written, saving
fails with an error naming the path. Unknown keys in the file stop
the server at startup with an error that names the key, so a typo never falls
back to a default silently. The effective configuration is logged at startup
as one `config` line.

| Key | Default | Meaning |
|-----|---------|---------|
| `data_dir` | `"./data"` | database (`webdavgo.db`, migration backups) and user files (`users/<name>/`) |
| `log_level` | `"info"` | `debug`, `info`, `warn` or `error` |
| `auth_cache_ttl` | `300` | seconds a successful login is remembered (see below); `0` disables |
| `shutdown_timeout` | `30` | seconds of grace for in-flight requests on SIGINT/SIGTERM |
| `read_header_timeout` | `10` | seconds a client may take to send the request headers |
| `idle_timeout` | `120` | seconds a keep-alive connection may stay idle |
| `max_request_body` | `1000` | body limit in KB for every method except PUT; larger → 413 |
| `allow_propfind_infinity` | `false` | allow PROPFIND `Depth: infinity` |
| `max_connections` | `256` | simultaneous connections per listener; further ones wait |
| `max_connections_per_ip` | `32` | simultaneous connections per client (IPv4 address, IPv6 /64) and listener; further ones are closed right after accept (see [Per-client limits](#per-client-limits)) |
| `http2_max_concurrent_streams` | `32` | parallel requests per HTTP/2 connection (Go's default would be 250) |
| `unauth_rate` | `20` | WebDAV requests without credentials per second and client (token bucket refill) |
| `unauth_burst` | `50` | bucket size for `unauth_rate`; beyond it such requests get 429 |
| `log_buffer_entries` | `2000` | log records kept in memory for **Admin → Live Log** |
| `default_quota` | `1` | storage quota of a new user in GB (decimal, 1 GB = 10^9 bytes); `0` = unlimited; prefilled in the *Add user* form; existing users keep theirs |
| `access_log` | `"/var/log/webdavgo/access.log"` | absolute path of the file for the `request` lines; `""` = stdout (see [Log files](#log-files)) |
| `server_log` | `"/var/log/webdavgo/webdavgo.log"` | absolute path of the file for every other record; may be the same file as `access_log`; `""` = stdout |
| `webdav_port` | `8080` | port of the WebDAV listener (1–65535); the certificate request sets `443` |
| `webdav_listen_address` | `""` | host name or IP address the WebDAV listener binds to, without port; empty = all interfaces |
| `webgui_port` | `8443` | port of the admin listener (1–65535) |
| `webgui_listen_address` | `""` | host name or IP address the admin listener binds to, without port; empty = all interfaces (see [Admin access](#admin-access)) |
| `tls_mode` | `"off"` | `off` (plain HTTP) or `acme` (TLS with an ACME certificate, see [Internet deployment](#internet-deployment)) |
| `require_tls` | `false` | with `tls_mode = "off"`, do not start the WebDAV listener on a non-loopback address (see below) |
| `domain` | — | public DNS name of the server; required with `tls_mode = "acme"` |
| `acme_email` | — | contact address for the ACME account; optional |
| `acme_ca` | `"production"` | `production` (Let's Encrypt), `staging` (Let's Encrypt staging) or an `https://` ACME directory URL |
| `acme_trial_ca` | `""` | CA of the certificate request's trial order: empty = Let's Encrypt staging when `acme_ca` is `production`, otherwise none; `none`; `staging`; or an `https://` URL |
| `acme_ca_root` | — | PEM file with root certificates to trust for the ACME directory (Pebble in tests) |
| `cert_dir` | `"<data_dir>/certs"` | ACME account and certificates, and the admin listener's self-signed certificate |
| `bruteforce_window` | `900` | seconds of the window for counting failed logins |
| `bruteforce_ip_threshold` | `10` | failures per client within the window that start a lockout |
| `bruteforce_lockout_base` | `60` | seconds of the first lockout; doubles with each further one |
| `bruteforce_lockout_max` | `3600` | seconds of the longest lockout |
| `bruteforce_account_threshold` | `20` | failures per username within the window that start the account throttle |
| `bruteforce_account_interval` | `5` | seconds between password checks while an account is throttled |
| `bruteforce_max_entries` | `100000` | size limit of the client table and of the account table |
| `body_read_idle_timeout` | `30` | seconds a request body may send nothing before it is aborted |
| `body_min_rate` | `1` | minimum average body rate in KB/s; `0` disables the check |
| `body_min_rate_grace` | `60` | seconds before `body_min_rate` is checked |
| `response_write_idle_timeout` | `30` | seconds a response may go unread before it is cut |
| `response_min_rate` | `1` | minimum average response rate in KB/s; `0` disables the check |
| `response_min_rate_grace` | `60` | seconds before `response_min_rate` is checked |

Every value is a plain number in one fixed unit, as the table says:
durations in whole seconds, sizes in KB and rates in KB/s (decimal, 1 KB =
1000 bytes, like the quota's GB). A commented example with every key is in
[`webdavgo.example.conf`](webdavgo.example.conf).

**Old value format.** Files from older versions wrote durations as strings
(`"30s"`, `"5m"`) and the listeners as `webdav_addr` / `webgui_addr`
(`[host]:port`). Whenever webdavgo reads its config file and finds such a
value, it converts it in place, line by line: each `*_addr` line becomes a
listen address and a port, and a duration becomes whole seconds (a value
that is not whole seconds is rounded up and logged at Warn). Every converted
key is logged with its old and new value. Plain integers are always read in
the units of the table: an older file's byte value such as
`max_request_body = 1048576` is read as KB and must be corrected by hand.

### Settings page

**Admin → Settings** shows every key above in one of six sections (Network &
listeners, TLS & domain, Connections & limits, Brute-force protection,
WebDAV, Logging), each with its saved value, a short description and its
default, plus the config file path. Every field is editable except where
there is a technical reason, which is shown next to the field: `data_dir`
(the database lives in it), the config file path (set by the service unit or
`-config`) and keys overridden by a command-line flag (`-data-dir`,
`-log-level`). Each section has three actions:

- **Save** writes the section's changed values to the config file, line by
  line as described above. Nothing takes effect yet. If any field is invalid,
  nothing is written and the error is shown next to the field.
- **Apply** saves the form first, then makes the section's saved values
  effective in the running server without a restart and without ending the
  admin session: limits, rates, timeouts read per request, brute-force and
  unauthenticated-rate parameters, `auth_cache_ttl`, `log_level` and
  `log_buffer_entries` at once. A changed port or listen address of a
  listener moves it: the new one starts, the old one finishes its running
  requests (up to `shutdown_timeout`) and closes; after moving the admin
  listener the page links to the new address, which is then the only one.
  In the TLS & domain section, `tls_mode = "acme"` works differently: Save
  and Apply both run the certificate request (see
  [Domain & certificate](#domain--certificate)), and the TLS values reach the
  file only once it has succeeded. `tls_mode = "off"` is saved at once; the
  domain and ACME fields are then disabled and not written.
  `read_header_timeout`, `idle_timeout`, `http2_max_concurrent_streams`,
  `max_connections`, `access_log`, `server_log`, `require_tls`, `cert_dir`
  and switching `tls_mode` back to `off` are marked "takes effect after
  service restart"; the page lists every saved value still waiting for one.
- **Reset to defaults** (after a confirmation) writes the default of every
  editable key of the section into the file, in place. It takes effect like
  any saved change. In the TLS & domain section that includes the domain and
  ACME keys (`tls_mode = "off"`, `domain = ""`, `acme_ca = "production"`, …),
  and it clears the values of a failed certificate request; the running TLS
  state stays as it is until a service restart.

A field whose saved value differs from the running one says so, with the
running value. **Admin → Status** shows usage, connections and activity; the
certificate status is in the TLS & domain section.

**Migration from older versions.** Older versions read `config.toml` and kept
the listener addresses and the Domain & certificate values in the database.
At startup, if `/etc/webdavgo/config.toml` (or a `-config` file named
`config.toml`) exists and `webdavgo.conf` next to it does not, webdavgo
creates `webdavgo.conf` from it; the old file is left untouched. Then every
configuration value still in the `settings` table is written into the file
(a value already set in the file wins; a stored default needs no line) and
deleted from the table. Each step is logged at Info. If the file cannot be
written, the server does not start, rather than run without those values.

There is deliberately no overall read or write timeout: a single upload or
download may take minutes on a slow link. Instead, every read of a request
body (PUT included) extends the connection's read deadline by
`body_read_idle_timeout`, and a body averaging less than `body_min_rate` once
`body_min_rate_grace` has passed is aborted. A client therefore cannot hold
the `max_connections` slots by starting uploads and then stalling or
trickling. An aborted PUT keeps the old file content and leaves no temporary
file. Each listener allows 64 KiB of request headers.

Responses get the same treatment in the other direction: every write pushes
the connection's write deadline out by `response_write_idle_timeout`, and a
response averaging less than `response_min_rate` after
`response_min_rate_grace` is cut (logged at Warn as `response aborted`). A
client that starts a large download and then stops reading therefore frees
its slot after 30 s; downloads at any speed above 1 KB/s are not affected.
On HTTP/2 connections at most `http2_max_concurrent_streams` requests run at
once per connection, so `max_connections` stays a meaningful bound.

## Running as a service

On SIGINT or SIGTERM (Ctrl-C, `systemctl stop`) the server stops accepting
connections, lets in-flight requests finish for up to `shutdown_timeout`,
closes the database and exits 0. Requests still running after the timeout are
cut; the log states how many connections were closed, and the exit code is
still 0. An interrupted upload never replaces the old file and its temporary
file is removed. A second Ctrl-C during the grace period ends the process
immediately.

Leftover `.webdavgo-tmp-*` files from a process that was killed hard
(`kill -9`, OOM, power loss) are deleted at the next start, before the
listeners open; each deleted file is logged at Warn.

## Authentication cache and request log

bcrypt (cost 12) takes about 180 ms per check on an Apple M4, and clients
such as the macOS Finder send many small requests. Successful user logins on
the WebDAV and `/api/v1/` paths are therefore remembered for `auth_cache_ttl`.
The cache
holds an HMAC-SHA256 of the password under a random key generated at process
start, never the password. A different or wrong password always goes through
bcrypt, failed logins are never cached, and a password reset or user deletion
drops the user's entry. The admin UI login always uses bcrypt. Share
recipients are unaffected (their token check is a SHA-256 lookup).

The cache only learns about password resets and deletions made through the
admin UI. If you change or delete a user directly in the database (for
example with `sqlite3`), the old password keeps working for up to
`auth_cache_ttl` on clients that logged in before. Restart the server, or
wait that long, after such a change.

Every request on the WebDAV listener produces one `request` line,
including rejected logins (401, no `user` field):

```
2026-10-27T17:09:01.123+01:00 INFO request method=PROPFIND path=/ client=192.0.2.10 user=alice status=207 auth=cache auth_ms=0 duration=1ms
```

The line is at Info, except for a 401 to a request without credentials
(`status=401 auth=none`) and a 429 to one (`status=429 auth=none`, refused by
the [unauthenticated rate limit](#per-client-limits)), which are at Debug: on
a public server those are mostly scanners (half of all journal lines in a
night on a test VPS). They are counted on the Activity card instead (see
[Status: activity](#status-activity)). A 429 with credentials (brute-force
lockout or throttle) stays at Info. The admin listener writes a `request` line too,
at Debug only, with `listener=admin`, `method`, `path` (never the query
string), `client`, `status` and `duration`.

`client` is the full remote IP (also for IPv6, where the brute-force
protection groups by /64).

`auth` is `cache`, `bcrypt`, `token` (share), `blocked` (429 from the
brute-force protection, no password check) or `none` (no credentials);
`auth_ms` is the time spent authenticating and is included in `duration`.

Authentication problems on the WebDAV listener get an extra Warn line next
to the `request` line. No password, token or code is ever logged.

| Message | When | Fields |
|---|---|---|
| `webdav auth failed` | user Basic Auth (WebDAV or `/api/v1/`) with credentials that failed the password check | `username` (as attempted), `client`, `method`, `path` |
| `share auth failure` | unknown share ID, or wrong recipient email or token (the line does not say which, like the 401); no line without credentials or with an empty share ID | `share_id`, `claimed_email` (both cut to 64 bytes), `client` |
| `share token expired` | correct share credentials after `expires_at` (401, not counted as a failure) | `share_id` (cut to 64 bytes), `client` |
| `auth refused: throttled` | 429 because the client is locked out or the account is throttled | `client`, `source` (`WebDAV user auth` or `share token`), `username` (user auth only), `scope` (`client` or `account`), `retry_after` |

Requests without credentials (`auth=none`, the normal 401 challenge) get no
extra line.

Errors that x/net/webdav reports for a request (`webdav internal error`,
`share webdav error`, with `status` and `err`) are at Warn for a 5xx and
for a fault of the local storage whatever the status (`ENOSPC`, `EDQUOT`,
`EIO`, `EROFS`, `EACCES`, `EPERM`; x/net answers e.g. a PUT on a full disk
with 405). Other client errors such as MKCOL on an existing collection (405)
or a missing file (404) are at Debug.

## Request limits

- Request bodies of every method except PUT are capped at `max_request_body`
  (413 Request Entity Too Large). PUT bodies are file uploads and unlimited.
- PROPFIND with `Depth: infinity`, or without a `Depth` header (which means
  infinity), is refused on the user and the share endpoint with 403 and the
  RFC 4918 §9.1 precondition body
  `<d:error xmlns:d="DAV:"><d:propfind-finite-depth/></d:error>`. Clients then
  walk the tree with `Depth: 1`. Set `allow_propfind_infinity = true` to allow
  it. Depth values other than `0`, `1` and `infinity` → 400. SEARCH is not
  affected.

### Per-client limits

A client is an IPv4 address or an IPv6 /64, as for the
[brute-force protection](#brute-force-protection).

- **Connections:** each client may hold `max_connections_per_ip` (32)
  connections per listener (WebDAV and admin are counted separately). A
  further connection is closed right after accept, before the TLS handshake
  and before any HTTP processing, and logged at Warn as `connection refused:
  per-IP limit` (`client`, `listener`, `limit`). A client is limited only
  while it holds all its connections; closing one frees its place.
- **Requests without credentials:** WebDAV requests that carry no
  credentials (every one of them would be answered 401) pass a token bucket
  per client: `unauth_rate` (20) tokens per second, `unauth_burst` (50) at
  most. Without a token the request gets **429 with `Retry-After`** (seconds
  until the next token, at least 1) and nothing else happens. It is logged
  at Warn as `unauthenticated requests throttled` (`client`, `listener`,
  `rate`, `burst`). Requests with credentials are never counted or limited
  by this; the brute-force protection handles those.
- Both refusal lines are written at most once per client and limit per
  minute; the next line carries `suppressed=N`, the refusals not logged in
  between. Both limits clear themselves within seconds and have no manual
  unlock. **Admin → Security** lists the clients they held back, the
  Activity card counts them.
- Memory: the connection counts only hold clients with open connections
  (at most `max_connections` per listener). The token buckets and the table
  of rate-limited clients each hold at most `bruteforce_max_entries`
  clients. An idle bucket (full again) is dropped within a minute; when the
  bucket table is full, an idle entry is evicted first, otherwise the one
  used longest ago, and this is logged once at Warn.

## Listener defaults

| Listener   | Default port | Default listen address |
|------------|--------------|------------------------|
| WebDAV     | `8080`       | all interfaces         |
| Web Admin  | `8443`       | all interfaces         |

Change them with `webdav_port` / `webdav_listen_address` and `webgui_port` /
`webgui_listen_address` in the config file or via **Admin → Settings**, which saves them to the file. They take
effect with Apply on the Settings page or on the next restart; connections
on the old listener finish their running requests. With
`tls_mode = "acme"` the WebDAV listener serves HTTPS only; the admin listener
always does.

Databases created before the admin listener moved to TLS may still hold
the old default `:8081` without having moved it. The migration into the
config file treats that as the new default `:8443` (logged at Info). Any
other value, and a `:8081` set deliberately later, is migrated as it is.

## Admin access

The admin listener (default `:8443`) speaks **HTTPS only**, also on
localhost; plain HTTP to that port gets a bare 400 and no page. TLS 1.2 is the
minimum.

- **Certificate.** On the first start webdavgo creates a self-signed ECDSA
  P-256 certificate, valid for 10 years, in `cert_dir`
  (`admin-selfsigned.crt`, key `admin-selfsigned.key` with mode 0600). Its
  names are `localhost`, `127.0.0.1`, `::1`, the hostname and every LAN
  address of the host at that time (link-local addresses excluded). It is
  only recreated when a file is missing, so the fingerprint stays the same
  across restarts; delete both files and restart to get one with new
  addresses.
- **Fingerprint check.** The browser warns about the self-signed certificate.
  Compare the SHA-256 fingerprint it shows (certificate details) with the one
  in the setup banner or in the log line printed at every start:

  ```
  2026-10-27T17:09:00.512+01:00 INFO "admin certificate" sha256=83:27:50:…:AC:49 path=…/certs/admin-selfsigned.crt
  ```

  On the command line: `openssl x509 -in <cert_dir>/admin-selfsigned.crt -noout -fingerprint -sha256`.
- **With `tls_mode = "acme"`**, a browser that asks for the configured
  `domain` (TLS SNI) gets the ACME certificate and no warning; access by IP
  address or `localhost` keeps the self-signed one.
- **Reachability.** By default (`:8443`) the admin listener binds all
  interfaces and is reachable from any network that can reach port 8443 –
  on a VPS without a firewall, that is the internet. The startup log line
  `INFO "webgui listener" … reach=…`, the setup banner, `setup-info`, the
  Settings page and the certificate request pages all state the address
  actually bound. To limit it, set `webgui_listen_address` in the config file
  (or on the Settings page) to a specific address, e.g. `"127.0.0.1"` for this
  host only, or filter the port in a firewall. With a loopback address, use
  an SSH tunnel from another machine and open `https://localhost:8443/admin/`
  locally:

  ```sh
  ssh -N -L 8443:localhost:8443 user@dav.example.com
  ```

### Two-factor authentication (TOTP)

Every admin needs TOTP (RFC 6238: SHA-1, 6 digits, 30 s). Login is two steps:
username and password, then a code from the authenticator app. Until the
second step is done the session can only open the code page (or log out),
and it expires after 5 minutes.

- **Enrolment.** An admin without TOTP (the first admin during setup, a new
  admin, existing admins after the upgrade, or after a reset) is sent to the
  enrolment page at the next login: QR code, the key in Base32 for manual
  entry and the `otpauth://` URI (issuer `webdavgo`, account
  `<username>@<domain or hostname>`). Enrolment is complete once one code is
  confirmed.
- **Recovery codes.** After enrolment, 10 recovery codes are shown **once**;
  only their SHA-256 hashes are stored. Each one can be entered instead of a
  TOTP code, once.
- **Replay protection.** A code is accepted for the current 30-second step
  and one step either side, but a step is accepted only once per admin: the
  same code cannot be used for a second login.
- **Brute force.** Wrong TOTP and recovery codes count as failed logins for
  the client and the account, exactly like wrong passwords; while throttled,
  the code page answers 429.
- **Reset.** On **Admin → Users**, an admin can reset another admin's TOTP;
  that admin enrols again at the next login. Resetting your own TOTP needs a
  valid current code.

**After updating from a version without TOTP:** enforced enrolment is
trust-on-first-use. Until an existing admin has enrolled, anyone who knows
that admin's password can sign in and register *their own* authenticator.
Sign in with every existing admin account and complete the enrolment right
after the update (or reset the passwords first).

**Lost authenticator and recovery codes:** run on the server, with the same
`-config` / `-data-dir` as the service:

```sh
sudo -u webdavgo webdavgo reset-totp <username>
```

Plain `sudo webdavgo reset-totp …` works too: started as root on Linux, the
command runs itself again as the `webdavgo` user, so it never leaves
root-owned files (`-wal`, `-shm`) in the data directory.

It removes the TOTP secret and recovery codes of that user and nothing else
(no password change); the next login goes to the enrolment page. It also
raises that user's session epoch in the database, so the running service
ends all of that user's admin sessions at their next request (logged at
Warn: `admin session ended: sessions were revoked outside this process`).
It works without the HTTP listeners (the service may keep running) and exits
non-zero if the database cannot be opened or the user does not exist.

`reset-totp` and `setup-info` never migrate the database schema; only the
service does, at startup. If the database's schema version differs from the
binary's, they refuse: after an update, restart the service first so it
migrates the database; an older binary than the database gives the usual
"newer than binary target" error.

### Sessions, CSRF and headers

- The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict`. The
  session ID changes after the second factor.
- Every POST carries a per-session CSRF token (hidden form field, or the
  `X-CSRF-Token` header that HTMX sends; either one matching is enough); a
  missing or wrong token → 403, and the page shows the rejection. Forms that
  change the session (login, TOTP, enrolment, sign-out, setup) are full page
  loads, never HTMX-boosted, so the page always carries the current token.
  POSTs whose `Origin` (or `Referer`, or `Sec-Fetch-Site` for browsers that
  still send `Origin: null`) is not the admin listener itself → 403.
- All admin responses carry `Content-Security-Policy: default-src 'self'`
  (plus `img-src 'self' data:` for the QR code; no inline scripts or styles),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: same-origin` (browsers then send a real `Origin` on the
  UI's own POSTs; nothing leaks to other sites); pages also
  `Cache-Control: no-store`.
- All sessions of a user end when the user is deleted, the password is reset
  or the TOTP is reset (also by `reset-totp` from the shell). Every admin request also checks that the user still
  exists and still is an admin.

### Security page

**Admin → Security** shows the brute-force state (see
[Brute-force protection](#brute-force-protection)): clients that are locked
out or were before (source, locked until, remaining lockout, failures in the
window and in total, number of lockouts, last failure) and throttled
accounts (source, remaining throttle, failures in the window and in total,
next allowed check, last failure), most recent first. WebDAV user auth
(including `/api/v1/`), share tokens and the admin login (password, TOTP
and recovery codes) share one limiter; the source column counts each
entry's failures per path, e.g. `admin login: 3, share token: 1`. **Unlock** removes a client's lockout
and resets its doubling; **Clear** ends an account throttle. Both are logged
at Info with the acting admin. Useful when your own NAT address got locked
out by another device; no restart is needed.

A third table, **Rate-limited clients**, lists the clients held back by the
[per-client limits](#per-client-limits): client, limit (connections per IP
or unauthenticated requests), listener, whether it is active, the remaining
time where there is one, refusals since the client was first recorded, and
the first and last refusal. A client is active while it holds all its
connections on a listener (no remaining time: it ends when a connection
closes) or has no token left, and for 60 s after a refusal. Listed are
clients active now or refused within the last 24 h, most recent first. The
table holds at most `bruteforce_max_entries` clients; when full, the one
refused longest ago among the inactive ones is dropped, and `+N not tracked`
says how many clients refused within 24 h were dropped or never recorded.
These limits clear themselves within seconds, so there is no unlock button.

## Deployment with `webdavgo install`

On Linux with systemd, one command sets up the service; everything else
happens in the browser:

```sh
sudo ./webdavgo install
```

It prints its plan first, then:

1. copies the running binary to `/usr/local/bin/webdavgo` (temporary file +
   rename; running `install` from a newer binary is the update path, and a
   running service is restarted to pick it up);
2. creates the system user and group `webdavgo` (no login shell, no home);
3. creates `/etc/webdavgo` and `/var/lib/webdavgo` (both webdavgo:webdavgo,
   0750; the service saves to its config file, through a temporary file and a
   rename in that directory);
4. writes `/etc/webdavgo/webdavgo.conf` (webdavgo:webdavgo, 0640) **only if
   it does not exist**, from `webdavgo.example.conf` with
   `data_dir = "/var/lib/webdavgo"`, `require_tls = true`,
   `access_log = "/var/log/webdavgo/access.log"` and
   `server_log = "/var/log/webdavgo/webdavgo.log"` set. If an older
   `/etc/webdavgo/config.toml` exists instead, `webdavgo.conf` is created
   from it and the old file is left untouched. An existing `webdavgo.conf` is
   kept as it is (only owner and mode are enforced); if it does not set
   `access_log` or `server_log`, the plan says that their defaults apply,
   so the log files are written under `/var/log/webdavgo` all the same;
5. writes `/etc/systemd/system/webdavgo.service`, a hardened unit: runs as
   `webdavgo`, `NoNewPrivileges`, `ProtectSystem=strict` with
   `ReadWritePaths=/var/lib/webdavgo /etc/webdavgo`, `ProtectHome`, `PrivateTmp`,
   `PrivateDevices`, kernel/cgroup protection, `RestrictAddressFamilies`,
   `RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`,
   `RestrictSUIDSGID`, `RestrictRealtime`, `ProtectClock`, `ProtectHostname`,
   `ProtectProc=invisible`, `SystemCallFilter=@system-service` (other calls
   fail with EPERM), `SystemCallArchitectures=native`, `UMask=0027`, and only
   `CAP_NET_BIND_SERVICE` (for port 443). `LogsDirectory=webdavgo` lets
   systemd create `/var/log/webdavgo` (webdavgo:webdavgo, 0750) and makes it
   writable inside `ProtectSystem=strict`. stdout and stderr go to journald
   (see [Log files](#log-files));
6. writes `/etc/logrotate.d/webdavgo` (0644; see [Log files](#log-files)),
   also when logrotate is not installed, which the plan then points out;
7. `systemctl daemon-reload` and `systemctl enable --now webdavgo`;
8. prints where the admin listener is bound and how far it is reachable, the
   admin URLs (`https://<LAN address>:8443/admin/`), the admin
   certificate's SHA-256 fingerprint and, while no admin exists, the setup URL
   with its token and a QR code. After an update that changes the database
   schema it first waits (up to two minutes, "Waiting for the service to
   migrate the database ...") until the restarted service has migrated it.

Running it again changes nothing that exists: data, config and the admin
certificate are kept. It refuses to run as non-root and on systems other than
Linux with systemd. `-root DIR` writes everything below `DIR` instead and skips
the user and systemctl steps (used by test.sh).

Then, in the browser: setup (admin account) → TOTP → **Domain &
certificate** → done.

**`webdavgo setup-info`** prints the same information again at any time
(`sudo webdavgo setup-info`; as root it
runs itself as the `webdavgo` user so that no root-owned database files
appear). The setup token lives in the database, valid for one hour; once it
has expired, `setup-info` issues a new one that the running service accepts.
After setup it only says that setup is complete.

**`webdavgo uninstall`** stops and disables the service and removes the
unit, `/etc/logrotate.d/webdavgo` and the binary. It keeps `/etc/webdavgo`,
`/var/lib/webdavgo` and `/var/log/webdavgo` and says so; `-purge` also
removes all three and the system user, after you type the hostname (or with
`-yes`).

### Log files

By default webdavgo writes two files, like nginx:

| File | Contents |
|------|----------|
| `/var/log/webdavgo/access.log` | the `request` lines of both listeners (see [Authentication cache and request log](#authentication-cache-and-request-log)) |
| `/var/log/webdavgo/webdavgo.log` | every other record: errors, security events (logins, lockouts), warnings, startup and shutdown |

Every line, in the files as on stdout and in the journal, is
**timestamp level message key=value...**: the time in RFC 3339 with
milliseconds in the server's local zone, the level (`DEBUG`, `INFO`, `WARN`,
`ERROR`), the message (in quotes when it contains spaces or other characters
that need them, quoted like a value), then the attributes. One line from
each file:

```
2026-10-27T17:09:01.123+01:00 INFO request method=PROPFIND path=/dav/ client=203.0.113.5 user=alice status=207 auth=cache auth_ms=0 duration=3ms
2026-10-27T17:09:02.456+01:00 WARN "webdav auth failed" username=x client=203.0.113.5 method=PROPFIND path=/dav/
```

`log_level` applies to both files. Read them as root or as a member of the
`webdavgo` group (files 0640, directory 0750):

```sh
sudo tail -f /var/log/webdavgo/webdavgo.log
sudo grep ' status=401 ' /var/log/webdavgo/access.log
```

The paths come from `access_log` and `server_log`; the defaults above apply
when the config does not set them. An empty value (`""`) sends those records
to stdout instead. A missing log directory is created (0750) before the
files are opened; if that fails, the server exits with an error naming the
directory and the reason. Only the server writes the files: `setup-info`,
`reset-totp`, `install` and `uninstall` always log to the terminal.

**journald still matters.** Records from before the config is loaded, and,
with `server_log` set, a copy of every Error record go to stdout/stderr and so
to the journal, which is why a failed start shows in `systemctl status
webdavgo` and `journalctl -u webdavgo`. A log file that cannot be opened is
reported there too, and the service does not start (no silent fallback to
stdout).

**Rotation** is done by logrotate with `/etc/logrotate.d/webdavgo`: daily,
14 files kept, compressed from the second rotation on (`delaycompress`),
empty files skipped. After moving the files, logrotate runs
`systemctl kill -s USR1 webdavgo.service`; on SIGUSR1 webdavgo opens new
files at the configured paths, switches to them and then closes the old
ones, so no record is lost, and logs `log files reopened`. If a new file
cannot be opened, it keeps writing to the old one and logs a Warn. To rotate
by hand: `sudo logrotate -f /etc/logrotate.d/webdavgo`.

**`require_tls = true`** (set by `install`): as long as `tls_mode` is `off`,
the WebDAV listener is not started on a network address (logged at Warn);
binding it to a loopback address (`webdav_listen_address = "127.0.0.1"`) is still allowed.
The admin listener runs as usual, so the Settings page can turn TLS on.

### Domain & certificate

**Admin → Settings → TLS & domain** (the first setup leads there after the
recovery codes). Set `tls_mode` to `acme`, enter the domain and, optionally,
an e-mail address for the CA, then **Save** or **Apply**. Both run the
certificate request with the submitted values, whose progress page
(`/admin/domain`) shows it step by step. The config file must only hold a
consistent configuration, so nothing of it is written before the certificate
has been obtained:

1. **DNS:** the domain's A/AAAA records are listed; if none of them is an
   address of this host, that is a warning only (normal behind a NAT router).
   A name that does not resolve at all is an error (except with a custom
   `acme_ca`, which may resolve names its own way).
2. **Port 443:** webdavgo opens a TLS listener on `:443`. Errors explain
   "permission denied" (CAP_NET_BIND_SERVICE) and "already in use" (another
   web server; a behind-proxy mode is not supported yet).
3. **Trial order** at Let's Encrypt staging when `acme_ca = "production"`,
   to keep mistakes away from production rate limits (`acme_trial_ca`
   overrides or disables it; a custom `acme_ca` gets none by default).
4. **Certificate** from `acme_ca`.
5. **Switch:** `tls_mode = "acme"`, `domain`, `acme_email`, `acme_ca`,
   `acme_trial_ca`, `acme_ca_root` and `webdav_port = 443` are saved to
   the config file in one write; the new TLS listener takes
   over and the old plaintext listener stops accepting connections and
   finishes its running requests (up to `shutdown_timeout`). No restart.

Failures are reported in plain English ("Port 443 is not reachable from the
internet – check port forwarding", "DNS for … does not point to this server",
…) with the CA's error in a details element; the old listener keeps running
and nothing was saved: the config file is unchanged, and the TLS & domain
section shows the submitted values with the error, to correct and send
again. The **finish page** (`/admin/domain/done`) shows the certificate status
(issuer, expiry, next renewal or ARI window, last error), the public WebDAV
URL `https://<domain>/` and a QR code of that URL for the iOS app.

## Internet deployment

With `tls_mode = "acme"` webdavgo gets and renews its own certificate from an
ACME CA (Let's Encrypt by default) using the TLS-ALPN-01 challenge, which is
answered on the WebDAV listener itself. There is no plaintext WebDAV listener
then, so Basic Auth credentials only ever travel over TLS. With
`tls_mode = "off"` the server logs a Warn at startup that credentials are sent
in clear text: use it for development or on a trusted LAN only.

### Setup

1. **DNS.** Create an A record (and AAAA, if the host has public IPv6) for
   the domain, pointing at your public address.
2. **Port forwarding.** Forward external TCP port **443** to the WebDAV
   listener (Admin → Settings, e.g. port 8080, or set `webdav_port` to 443 directly).
   The CA always validates on port 443; other external ports cannot work with
   TLS-ALPN-01.
3. **The admin port** (default 8443) needs no forwarding. Bound to all
   interfaces it is reachable from every network that can reach the host on
   that port; restrict it with `webgui_listen_address` or a firewall and use an SSH
   tunnel for remote administration (see [Admin access](#admin-access)).
4. **Config** (or use [Settings → TLS & domain](#domain--certificate)
   instead):

   ```toml
   tls_mode   = "acme"
   domain     = "dav.example.com"
   acme_email = "admin@example.com"   # optional, for expiry notices
   acme_ca    = "staging"             # first; see below
   ```

5. Start the server. It opens the listener first, then obtains the
   certificate in the background; the log shows `certificate obtained` and
   `certificate in use` with the expiry date, or `certificate obtain failed`
   with the error at Error level. CertMagic retries failures with backoff.
6. Once a staging certificate is obtained (clients will not trust it yet),
   set `acme_ca = "production"` and restart. Starting with staging keeps
   configuration mistakes away from Let's Encrypt's production rate limits.

The listener speaks HTTP/1.1 and HTTP/2, TLS 1.2 minimum with Go's default
cipher suites, and sends
`Strict-Transport-Security: max-age=31536000; includeSubDomains` on every
response (no `preload`; there is no OCSP stapling, as Let's Encrypt no longer
runs OCSP). Plain HTTP sent to the TLS port is not served: Go answers 400
or closes the connection, without ever asking for credentials.

**Renewal** needs no configuration. There are no fixed deadlines: CertMagic
renews when a third of the certificate's lifetime is left, or earlier when
the CA's ACME Renewal Information (ARI, RFC 9773) says so, which also covers
shorter certificate lifetimes. **Admin → Settings → TLS & domain** shows the domain, the
issuer, the certificate's expiry, the next renewal (the time CertMagic picked
in the CA's ARI window, or the estimate "a third of the lifetime left"), the
last successful obtain or renewal, the last error, and a warning once less
than a third of the lifetime is left (renewal is then overdue).

**Back up `cert_dir`** (default `<data_dir>/certs`) together with
`data_dir`. It holds the ACME account and the certificate, so a restart or a
restored backup reuses them instead of placing a new order.

### Brute-force protection

Applies to user Basic Auth (WebDAV and `/api/v1/`), share auth (`/s/{id}/`)
and the admin login (password and TOTP step). A client is an IPv4 address or
an IPv6 /64.
`X-Forwarded-For` is ignored, so behind a reverse proxy all clients would
share the proxy's address.

- **Per client:** `bruteforce_ip_threshold` failures within
  `bruteforce_window` lock the client out for `bruteforce_lockout_base`,
  doubling with each further lockout up to `bruteforce_lockout_max`. During
  the lockout no password is checked: requests get **429 with
  `Retry-After`**, even with the correct password, never 401 (share clients
  treat 401 as revocation). A successful login does not end a lockout. The
  admin login page shows "Too many failed login attempts" with status 429.
- **Already logged-in devices keep working:** credentials answered from the
  auth cache pass during a lockout. So behind a shared NAT, one device
  guessing passwords does not cut off the others that were already logged in.
- **Shares:** a correct share token always passes (it has 256 bits and is
  checked without bcrypt). Wrong tokens count toward the client; during its
  lockout they get 429 instead of 401.
- **Per account:** after `bruteforce_account_threshold` failures for one
  username within the window, from any number of clients, only one password
  check per `bruteforce_account_interval` runs for it; other uncached
  attempts get 429 with `Retry-After`. Accounts are never locked hard, which
  would let anyone lock out the real user.
- Unknown usernames are checked against a dummy bcrypt hash, so they take as
  long as wrong passwords for existing users and do not reveal which
  usernames exist.
- Requests without credentials still get the normal 401 challenge (beyond
  `unauth_rate`, 429; see [Per-client limits](#per-client-limits)).
- Lockouts and account throttles are logged at Warn with the client or
  username, the failure count and the duration. Every request refused with
  429 is logged at Warn: `auth refused: throttled` on the WebDAV listener,
  `login refused: throttled` on the admin listener. All state is in memory,
  bounded to `bruteforce_max_entries` (100 000) clients and as many
  usernames, and is reset by a restart. When a table is full, a locked-out
  client or a throttled account is never dropped to make room (that would let
  an attacker end their own lockout by flooding the table); the account
  table drops the one seen longest ago among the others. **Admin → Security** shows it and can unlock clients and accounts.

## Test

```sh
bash test.sh
```

Starts a fresh server in a temporary directory (the repo's `data/` is never
touched), runs all 150 success criteria (migrations, setup wizard, per-user
WebDAV isolation, PROPFIND creationdate, full SEARCH grammar, admin CRUD,
settings, email-bound shares, sync conformance, href encoding, config file and flags, graceful
shutdown, auth cache, request limits, brute-force protection, slow request
bodies, a `-race` shutdown under load, TLS via ACME, admin hardening (TLS-only
admin listener, TOTP, CSRF, headers, session invalidation, Security page,
`reset-totp`), deployment (`install`/`uninstall -root`, `require_tls`,
`setup-info`, settings precedence, the Domain & certificate page), HTTP/2
stream limit, slow reads, schema checks of the CLI commands, log files and
reopen on SIGUSR1, and regression), prints PASS/FAIL for each, then stops the
server. The server runs with a config file inside the temporary directory.
Exits non-zero if any criterion fails. Needs ports 443, 8080, 8443 and 9443 free,
plus `curl`, `jq`, `sqlite3` and `openssl`. The
brute-force criteria use both `127.0.0.1` and `[::1]` as distinct clients, so
IPv6 loopback must be enabled. Admin requests trust the self-signed
certificate through its file (`curl --cacert`), not `-k`.

TOTP codes for the admin logins come from `tools/totpcode`, a small Go
program that test.sh builds once; it is not part of the server binary.
`oathtool` is not installed on macOS by default, and a separate
implementation also checks the server's. The server accepts each 30-second
step only once per admin, so test.sh uses the steps either side of the
current one and waits for the next step when it logs in more often than
that; a run takes up to a few minutes longer for it.

The ACME criteria (C98–C103, C119) run against
[Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's ACME test
server, with `pebble-challtestsrv` as its DNS server (every name resolves to
127.0.0.1). Install both once:

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
```

test.sh finds them in `$(go env GOPATH)/bin` and Pebble's test certificates in
the Go module cache; without them the ACME criteria fail. Pebble validates
TLS-ALPN-01 for real (no `PEBBLE_VA_ALWAYS_VALID`) by connecting to port 8080,
the test WebDAV listener. It also uses ports 14000, 15000, 8053 and 8055.
C98 is also the regression test for CertMagic's handling of our own
listener answering TLS-ALPN-01; run it after every CertMagic update.

The Domain & certificate criteria (C137–C140) restart Pebble so that it
validates on port **443**, where the page moves the WebDAV listener. macOS
lets unprivileged processes bind `:443`; on Linux, run with
`CAP_NET_BIND_SERVICE` or lower `net.ipv4.ip_unprivileged_port_start`.

## File names and hrefs (clients)

Every `<d:href>` in PROPFIND and SEARCH responses, on the user endpoint and
under `/s/<share_id>/`, is a percent-encoded URI reference (RFC 4918 §8.3):
each path segment is encoded, `/` separators and the trailing `/` of a
collection are kept, and the result is XML-escaped (`&` → `&amp;`). A file
`Straße & „Plan“.txt` is listed as
`/Stra%C3%9Fe%20&amp;%20%E2%80%9EPlan%E2%80%9C.txt`. Clients can send an
href unchanged as the request path or `Destination` of GET, PUT, DELETE,
MOVE and COPY, and a collection href as the SEARCH scope.

**SEARCH scope.** The scope `<d:href>` is a URI reference (RFC 5323 §5.4,
RFC 3986 §4.1) and is percent-decoded; a query or fragment is ignored. The
scope resolves against the endpoint root: the user's root, or the share root
at `/s/<share_id>/`. At a share, a path starting with `/s/<share_id>` (as in
the share's own hrefs) is taken under that prefix; any other path stays
relative to the share root, as Nextcloud-style clients expect. An absolute
URI (`http://host/...`) is accepted only when scheme and host match the
request.

| Scope | Answer |
|-------|--------|
| not a valid URI reference (e.g. a raw `100%` or `%#`) | 400 |
| does not exist, other scheme or host, or outside the share | 409 with `<d:error><d:search-scope-valid><d:response>` naming the scope with `404` (RFC 5323 §2.2.2) |
| not a collection | 400 |

Clients that sent names raw must now percent-encode the scope; raw
non-ASCII characters and spaces are still accepted, but a raw `%`, `?` or
`#` is read with its URI meaning.

The server does not normalize Unicode: it stores the bytes of the name the
client sends and returns exactly those bytes, percent-encoded. Depending on
the client, `ü` may arrive precomposed (NFC) or decomposed (NFD). On a Linux
filesystem the two forms are two different names; APFS treats them as the
same file.

## Conditional requests & ETags

Sync clients rely on these standard HTTP/WebDAV semantics; they apply equally
to the user endpoint and to share endpoints (`/s/<share_id>/`).

**ETag.** Every method reports the same strong ETag for a file: GET/HEAD and
PUT in the `ETag` header, PROPFIND and SEARCH as `getetag`. Format:
`"<mtime-unix-nanoseconds-hex><size-hex>"` — quoted, never `W/`. The ETag a
PUT returns can be sent unchanged as `If-Match` on the next request. Because
the tag uses the nanosecond mtime, it changes on every write even within the
same second on filesystems with sub-second timestamps (ext4, APFS, XFS). On
filesystems with coarse mtimes (FAT, some network filesystems) two writes of
the same size within one timestamp tick can produce the same ETag.

**Preconditions (RFC 9110 §13).**

| Header | Methods | Fails with 412 when |
|--------|---------|---------------------|
| `If-Match: "<etag>", …` | PUT, DELETE | the file is missing, or no listed tag strongly matches (weak `W/` tags never match) |
| `If-Match: *` | PUT, DELETE | the file is missing |
| `If-None-Match: "<etag>", …` | PUT | a listed tag matches the current ETag (weak comparison) |
| `If-None-Match: *` | PUT | the file exists (create-only upload) |

Check and write are atomic per file: concurrent writers with the same
`If-Match` get exactly one success and one 412. GET/HEAD support
`If-None-Match` and `If-Modified-Since` (→ 304) as before.

**Atomic PUT.** The body is written to a temporary file
(`.webdavgo-tmp-*`) in the target directory and renamed over the target only
after the whole body arrived. An aborted upload leaves the previous content
untouched. Temporary files never appear in PROPFIND or SEARCH, and requests
addressing that prefix get 403. Status codes are unchanged: 201 on success
(create or overwrite), 409 when the parent collection is missing.

**401 vs 429 vs 503.** 401 means wrong or revoked credentials only. When the
database cannot be read during authentication, the server answers 503 with
`Retry-After: 30`; when the brute-force protection holds a client or an
account back, it answers 429 with `Retry-After`. Share recipients therefore
never mistake a server fault or a lockout for a revoked share.

**Download headers.** Every GET/HEAD (and POST, which x/net answers like
GET) of a stored file, on the user and on the share endpoint, carries
`Content-Disposition: attachment; filename*=UTF-8''<name>`,
`X-Content-Type-Options: nosniff` and
`Content-Security-Policy: default-src 'none'; sandbox`, so a browser saves an
uploaded HTML or SVG file instead of rendering it on the server's origin.
`Content-Type`, `ETag`, `Last-Modified`, `Content-Length` and range handling
are unchanged. Every response of the WebDAV listener, errors included,
carries `X-Frame-Options: DENY`.

## Storage quota

Every user has a quota in bytes; 0 means unlimited. New users get
`default_quota` (default 1 GB = 1,000,000,000 bytes; set on **Admin →
Settings → Users**, effective on Apply) unless the admin enters another
value; changing it does not touch existing users. The migration
to schema v4 gave every existing user 1 GB. The admin sets the quota in GB
on **Admin → Users** (when adding a user, or per user with *Set quota*),
which also shows each user's usage and the totals: used by all users, and
size and free space of the filesystem holding the data directory.

Usage is the total size of the user's files. It is kept in the database,
updated with every write, and recounted from disk at every start, so a
counter that drifted is correct again after a restart.

| Request | Effect on usage |
|---------|-----------------|
| PUT | the growth: new size minus the size of the file it replaces |
| COPY | the size of the copied file or tree, minus what an overwritten destination held |
| MOVE | none, except that an overwritten destination is freed |
| DELETE | the size of the deleted file or tree is freed |

A write that would pass the quota gets `507 Insufficient Storage` with the
RFC 4331 `DAV:quota-not-exceeded` error body. With a `Content-Length` it is
refused before the body is read; a chunked upload stops as soon as it passes
the quota, and its partial file is removed. A user over quota can still
read, list, move, delete and overwrite with smaller content. Writes through
a share count against the share owner; recipients have no quota of their
own.

PROPFIND on a collection returns `DAV:quota-available-bytes` and
`DAV:quota-used-bytes` (RFC 4331) when requested by name; they are not part
of `allprop`. For an unlimited user, `quota-available-bytes` is the free
space of the data filesystem. A share reports only `quota-available-bytes`,
the owner's remaining quota; `quota-used-bytes` is answered as not found
(404 propstat), since the owner's total usage is no business of the
recipient.

## SEARCH ordering and limits

`getlastmodified` is an HTTP-date (`Fri, 16 Oct 2026 12:00:00 GMT`); date
literals in `<d:where>` may use that form, RFC 1123 with a numeric zone
(`date -uR`), or RFC 3339, and are compared at whole-second granularity.

The SEARCH response carries a `Date` header taken **before** the tree walk,
so `Date - 1 s` is a safe watermark for the next `getlastmodified > T` query.

```xml
<d:orderby>
  <d:order><d:prop><d:getlastmodified/></d:prop><d:ascending/></d:order>
</d:orderby>
<d:limit><d:nresults>100</d:nresults></d:limit>
```

- Sortable properties: `getlastmodified`, `creationdate`, `getcontentlength`,
  `displayname`, `getcontenttype`, `getetag` (strings compare ASCII
  case-insensitively). Others → 400.
- Default direction is ascending; earlier `<d:order>` elements take
  precedence; ties are broken by href. A missing value sorts as the lowest
  value.
- Without `<d:orderby>`, results are sorted by href.
- `nresults` must be a positive integer (else 400); the first N results after
  sorting are returned.

## Email-bound shares

### Lifecycle

1. A webdavgo user (the *owner*) calls `POST /api/v1/shares` — authenticated
   via Basic Auth with their webdavgo username and password.
2. The server generates a `shr_<16hex>` share ID and a `shr_tok_<64hex>` raw
   token (only SHA-256 hash stored). Both are returned **once** in the 201
   response.
3. The owner distributes the `share_url` (`/s/<share_id>/`) and `access_token`
   to the recipient through any out-of-band channel.
4. The recipient accesses the share via WebDAV at `/s/<share_id>/`, using
   Basic Auth with their email as username and the raw token as password.
5. The owner (or an admin via the admin UI) can delete the share at any time.
   The recipient's next request returns 401.

**Orphan shares**: if the owner deletes the shared directory after creating the
share, the recipient will receive 404 on PROPFIND of the share root. The share
row remains in the database until explicitly revoked.

### Create a share

```sh
curl -X POST http://localhost:8080/api/v1/shares \
     -u alice:alicepass1 \
     -H 'Content-Type: application/json' \
     -d '{
           "path": "/forms/birthday",
           "recipient_email": "bob@example.com",
           "permission": "read-write",
           "expires_at": null
         }'
```

Response (201):

```json
{
  "share_id": "shr_a1b2c3d4e5f60718",
  "owner_username": "alice",
  "path": "/forms/birthday",
  "recipient_email": "bob@example.com",
  "permission": "read-write",
  "access_token": "shr_tok_<64 hex chars>",
  "share_url": "/s/shr_a1b2c3d4e5f60718/",
  "created_at": "2026-06-04T10:00:00Z",
  "expires_at": null
}
```

`access_token` is only present in this 201 response; it is never returned again.

### List your shares

```sh
curl http://localhost:8080/api/v1/shares -u alice:alicepass1
```

### Get a specific share

```sh
curl http://localhost:8080/api/v1/shares/shr_a1b2c3d4e5f60718 -u alice:alicepass1
```

### Delete (revoke) a share

```sh
curl -X DELETE http://localhost:8080/api/v1/shares/shr_a1b2c3d4e5f60718 \
     -u alice:alicepass1
```

Returns 204. The recipient's next request returns 401.

### Access a share as the recipient

```sh
# PROPFIND (list directory)
curl -X PROPFIND \
     -u "bob@example.com:shr_tok_<64hex>" \
     -H "Depth: 1" \
     http://localhost:8080/s/shr_a1b2c3d4e5f60718/

# PUT (upload a file, requires read-write share)
curl -X PUT \
     -u "bob@example.com:shr_tok_<64hex>" \
     --data-binary @localfile.txt \
     http://localhost:8080/s/shr_a1b2c3d4e5f60718/localfile.txt

# SEARCH (find recently modified files)
curl -X SEARCH \
     -u "bob@example.com:shr_tok_<64hex>" \
     -H 'Content-Type: application/xml' \
     --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where/>
  </d:basicsearch>
</d:searchrequest>' \
     http://localhost:8080/s/shr_a1b2c3d4e5f60718/
```

### Method gate inside a share

| Method               | read share | read-write share |
|----------------------|-----------|-----------------|
| OPTIONS, GET, HEAD   | ✓         | ✓               |
| PROPFIND, SEARCH     | ✓         | ✓               |
| PUT, DELETE, MKCOL   | 403       | ✓               |
| MOVE, COPY           | 403       | ✓ (within share only) |
| LOCK, UNLOCK         | 501       | 501             |

MOVE/COPY destinations must start with `/s/<same_share_id>/`. Cross-share or
absolute destinations return 403.

### Admin UI

`/admin/shares` lists all shares across all owners with a **Revoke** button per
row. Revoked shares become immediately inaccessible (401 on next access).

`/admin/status` shows **Active shares: N**.

### Status: connections

**Admin → Status** lists the open connections on both listeners (`webdav`
and `admin`), refreshed every 2 s while the page is open: remote IP,
protocol (HTTP/1.1 or HTTP/2, known after the first request), connected
since, identity (username, `share <id>` for `/s/<id>`, an admin's name, or
`unauthenticated`), the running requests (method and path; for HTTP/2 every
active stream), bytes received and sent on the wire (TLS included) and the
transfer rate since the previous refresh. Query strings are never shown. A
connection leaves the list when it closes.

The polling requests (`/admin/status/connections`, `/admin/status/activity`,
`/admin/logs/entries`) need a valid admin session but do not extend its 24 h sliding expiry, so a
tab left open does not keep the session alive. When the session has ended, the
poll answers with `HX-Redirect` and the browser goes to the login page.

### Status: activity

The **Activity** card above the connections shows traffic and
authentication statistics, refreshed every 30 s while the page is open, in
two columns: the last hour and the last 24 h. If the process started less
than 24 h ago, the second column says `last 24 h (restarted X h ago)`, or
`(restarted <1 h ago)` in the first hour. Everything
is counted in memory only and starts at zero after a restart.

Traffic, per listener (`webdav`, `admin`):

- open connections now, the peak of open connections, the peak of open
  connections from a single client (compare with `max_connections_per_ip`)
  and new connections
- finished requests by status class (2xx · 3xx · 4xx · 5xx)
- WebDAV only: unauthenticated 401, i.e. 401 answers to requests without
  credentials (their `request` lines are at Debug); the admin listener never
  answers 401
- bytes received and sent on the wire (TLS included, as in the connections
  table)
- TLS handshake errors (the `TLS handshake error` messages of Go's HTTP
  server; counted even when `log_level` hides them)

Authentication:

- failed attempts by source: WebDAV user (WebDAV and `/api/v1/`), share
  token, admin password, admin second factor (TOTP, recovery code and the
  code for resetting one's own TOTP). A failed attempt is a credential that
  was checked and was wrong; requests without credentials, requests refused
  with 429 and wrong codes while enrolling TOTP (logged as `login failed:
  totp enrolment code`) are not failures.
- expired share tokens used (separately, not counted as failures)
- distinct client IPs with at least one failed attempt
- active users and active shares: distinct identities that authenticated
  successfully
- admin logins (completed with the second factor)

Automatic limits, one block per limit, each with what is active now, how
many distinct clients (accounts for throttles) the limit held back in the
last hour and 24 h, and what it refused:

- **Client lockouts:** clients locked out now; clients with a lockout that
  started or a request refused; lockouts started; requests refused with 429
  because the client is locked out (all listeners).
- **Account throttles:** accounts throttled now; accounts with a throttle
  that engaged or a request refused; throttles engaged; requests refused
  with 429 because the account is throttled (all listeners). Together with
  the line above this is the former "Requests refused with 429".
- **Per-IP connection limit:** clients active now (holding all their
  connections on a listener, or refused within the last 60 s); clients with
  a refused connection; connections refused, per listener (webdav · admin).
- **Unauthenticated rate limit:** clients active now (no token left, or
  refused within the last 60 s); clients with a refused request; requests
  refused with 429.

Below, a bar per clock hour (UTC) of the last 24 h shows the failed
attempts stacked by source; hovering a bar shows the exact numbers. Two top
lists show the five client IPs and the five attempted usernames (WebDAV user
and admin) with the most failed attempts in the last 24 h, with the sources
involved; a username is marked `exists` or `unknown` from the user table at
the time the card is rendered. A third top list shows the five client IPs
with the most unauthenticated 401s in the last 24 h.

Counters are kept in 5-minute slots (288 for 24 h), so "last hour" covers
55–60 minutes and "last 24 h" 23 h 55 min to 24 h. Top lists and distinct
counts are kept per clock hour (24 buckets) and remember when each key was
last seen, so distinct counts cover exactly the last hour and 24 h, while
the top lists cover the current and the 23 previous clock hours. Each hourly
table holds at most 1000 keys (client IPs, usernames, users, shares,
clients with unauthenticated 401s, and the clients or accounts per
automatic limit); beyond that, a top list shows `+N not tracked` and a
distinct count is prefixed with `≥`. Usernames are stored with at most 64
bytes. The peak of open connections from a single client is recorded when a
client opens a connection; connections held since an earlier period count
from the client's current number.

### Live Log page

**Admin → Live Log** shows the newest log records of the running process
(`log_buffer_entries`, default 2000), newest first, with a minimum-level
filter, a case-insensitive text filter and optional auto-refresh every 2 s.
At most the newest 500 matching records are shown. The buffer gets a copy of every record that goes to stdout/journald or to the
[log files](#log-files); it is lost on restart, the log is not. Each buffered record keeps at most 256 bytes of
message and 1024 bytes of attributes, cut at a UTF-8 boundary and marked
`…(+N bytes)`; the journal or log file keeps the full line. Admin logins are logged with username and
client IP: `login password accepted`, `login success`, `login failed`,
`login failed: second factor` (`kind=totp` or `recovery`), `login failed:
totp enrolment code`, `own totp reset refused: invalid code` and `login
refused: throttled`. For the WebDAV listener's lines see
[Authentication cache and request log](#authentication-cache-and-request-log).
No password, token or code is ever logged.

Errors of Go's HTTP server itself (`http.Server.ErrorLog`) go through the
same logger with `listener=webdav` or `listener=admin` and their original
text: `TLS handshake error …` at Debug (on a public port mostly scanners, so
they stay out of the journal at `log_level = "info"`), `http2: received
GOAWAY …` at Debug (a browser closing its HTTP/2 connection), everything
else at Warn. `admin request rejected: cross-origin`, `webdav internal
error` and `password reset` carry `client`.

## Emergency recovery

If you have changed the listener addresses to something unreachable, edit
the config file (`/etc/webdavgo/webdavgo.conf` for an installed service):
remove or comment out the `webdav_port`, `webdav_listen_address`,
`webgui_port` and `webgui_listen_address` lines to get the defaults (ports
8080 and 8443, all interfaces) back, then restart. The admin UI is then at
`https://localhost:8443/admin/` (HTTPS only).

To undo what the certificate request saved and go back to plain HTTP
on port 8080, set `tls_mode = "off"` and remove or comment out the
`webdav_port` line in the same file, then restart.

With `require_tls = true` (installed services) WebDAV then stays off until
TLS is set up again. For a
lost second factor see `reset-totp` under
[Two-factor authentication](#two-factor-authentication-totp); for your own
client locked out by the brute-force protection, restart the server (the
state is in memory) or unlock it on **Admin → Security** from another
address.

## Intentionally out of scope

- Behind-proxy mode (`X-Forwarded-For`), DNS-01 challenges, own certificates
- Environment variables for configuration
- Cross-user shares where the recipient is themselves a webdavgo user with
  their own filesystem (a recipient is identified solely by email and holds a
  share-specific token)
- Server-side email / invite delivery (the owner distributes the share URL and
  token through any channel)
- Anonymous / public shares (no email binding)
- Orphan-share cleanup (owner deletes the shared directory → recipient sees
  404; share row remains until explicitly revoked)
- Persistent locks (lock state lives in memory, lost on restart)
- Share quota
- Invite-link onboarding
- Schema migration framework
- Per-user app tokens (`tok_` prefix) for device/app auth without passwords

## What comes next

- Release pipeline (signed binaries) and self-update
- Behind-proxy mode
- Invite-link flow for adding users

## License

Copyright (C) 2026 Jörn Feuerabend

This program is licensed under the GNU Affero General Public License,
version 3 only (AGPL-3.0-only). See [LICENSE](LICENSE).
Third-party components and their licenses are listed in
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
