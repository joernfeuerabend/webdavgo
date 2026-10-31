# Configuration

All configuration lives in one file, `webdavgo.conf`: flat `key = value`
lines (TOML syntax), `#` starts a comment. Without `-config`, webdavgo reads
`/etc/webdavgo/webdavgo.conf`. If that file, or the one given with
`-config`, does not exist, the server creates it (and its directory) from
[`webdavgo.example.conf`](../cmd/webdavgo/webdavgo.example.conf), i.e.
with the default values below, logs that at Info, and reads it. If it
cannot be created, the server exits with an error naming the path and the
reason. `setup-info` and
`reset-totp` never create it: they need the service's file. Every key is
optional. The database holds runtime data only (users,
shares, quota counters, setup token, session epochs), no configuration.

| Flag | Meaning |
|------|---------|
| `-config <path>` | config file to read and save to (default `/etc/webdavgo/webdavgo.conf`) |
| `-data-dir <dir>` | overrides `data_dir` |
| `-log-level <level>` | overrides `log_level` |

Subcommands: `install`, `uninstall` (see [Deployment](installation.md#deployment-with-webdavgo-install)),
`setup-info` and `reset-totp` (see [Admin access](administration.md#admin-access)),
`healthcheck` (see [Health checks](administration.md#health-checks)).

Precedence: **flag > config file > default.** The admin UI's **Settings**
page edits every key of the same file (see [Settings page](#settings-page)).
The certificate request also writes `webdav_port = 443`. A save rewrites only the line of each changed key. If a key
has no active line but a commented-out `#key = ...` line, that line is
activated, otherwise `key = value` is appended at the end. Comments, blank
lines, order and your own edits stay as they are. The file is written
atomically (temporary file in the same directory, then rename) and keeps its
mode and owner. There are no backup files. If it cannot be written, saving
fails with an error naming the path. Unknown keys in the file stop
the server at startup with an error that names the key, so a typo never falls
back to a default silently. The effective configuration is logged at startup
as one `config` line.

| Key | Default | Meaning |
|-----|---------|---------|
| `data_dir` | `"./data"` | database (`webdavgo.db`, migration backups) and user files (`users/<name>/`) |
| `log_level` | `"info"` | `debug`, `info`, `warn` or `error` |
| `auth_cache_ttl` | `300` | seconds a successful login is remembered (see [Authentication cache](administration.md#authentication-cache-and-request-log)), `0` disables |
| `shutdown_timeout` | `30` | seconds of grace for in-flight requests on SIGINT/SIGTERM |
| `read_header_timeout` | `10` | seconds a client may take to send the request headers |
| `idle_timeout` | `120` | seconds a keep-alive connection may stay idle |
| `max_request_body` | `1000` | body limit in KB for every method except PUT, larger → 413 |
| `max_dead_props_size` | `0` | maximum total size in KB of the dead properties of one resource, a PROPPATCH that would exceed it fails with 507 for the properties concerned (see [Dead properties](clients.md#dead-properties)). `0` = unlimited |
| `allow_propfind_infinity` | `false` | allow PROPFIND `Depth: infinity` |
| `max_connections` | `256` | simultaneous connections per listener, further ones wait |
| `max_connections_per_ip` | `32` | simultaneous connections per client (IPv4 address, IPv6 /64) and listener. Further ones are closed right after accept (see [Per-client limits](#per-client-limits)) |
| `http2_max_concurrent_streams` | `32` | parallel requests per HTTP/2 connection (Go's default would be 250) |
| `unauth_rate` | `20` | WebDAV requests without credentials per second and client (token bucket refill) |
| `unauth_burst` | `50` | bucket size for `unauth_rate`, beyond it such requests get 429 |
| `log_buffer_entries` | `2000` | log records kept in memory for **Admin → Live Log** |
| `default_quota` | `1` | storage quota of a new user in GB (decimal, 1 GB = 10^9 bytes), `0` = unlimited. Prefilled in the *Add user* form, existing users keep theirs |
| `access_log` | `"/var/log/webdavgo/access.log"` | absolute path of the file for the `request` lines, `""` = stdout (see [Log files](administration.md#log-files)) |
| `server_log` | `"/var/log/webdavgo/webdavgo.log"` | absolute path of the file for every other record. May be the same file as `access_log`, `""` = stdout |
| `webdav_port` | `8080` | port of the WebDAV listener (1-65535), the certificate request sets `443` |
| `webdav_listen_address` | `""` | host name or IP address the WebDAV listener binds to, without port. Empty = all interfaces |
| `webgui_port` | `8443` | port of the admin listener (1-65535) |
| `webgui_listen_address` | `""` | host name or IP address the admin listener binds to, without port. Empty = all interfaces (see [Admin access](administration.md#admin-access)) |
| `health_enabled` | `false` | run the health listener (see [Health checks](administration.md#health-checks)) |
| `health_bind` | `"127.0.0.1"` | host name or IP address the health listener binds to, without port. Empty = all interfaces |
| `health_port` | `8082` | port of the health listener (1-65535). Must differ from `webdav_port` and `webgui_port` |
| `tls_mode` | `"off"` | `off` (plain HTTP) or `acme` (TLS with an ACME certificate, see [Internet deployment](installation.md#internet-deployment)) |
| `require_tls` | `false` | with `tls_mode = "off"`, do not start the WebDAV listener on a non-loopback address (see [`require_tls`](installation.md#deployment-with-webdavgo-install)) |
| `domain` | none | public DNS name of the server, required with `tls_mode = "acme"` |
| `acme_email` | none | contact address for the ACME account, optional |
| `acme_ca` | `"production"` | `production` (Let's Encrypt), `staging` (Let's Encrypt staging) or an `https://` ACME directory URL |
| `acme_trial_ca` | `""` | CA of the certificate request's trial order: empty (Let's Encrypt staging when `acme_ca` is `production`, otherwise none), `none`, `staging` or an `https://` URL |
| `acme_ca_root` | none | PEM file with root certificates to trust for the ACME directory (Pebble in tests) |
| `cert_dir` | `"<data_dir>/certs"` | ACME account and certificates, and the admin listener's self-signed certificate |
| `bruteforce_window` | `900` | seconds of the window for counting failed logins |
| `bruteforce_ip_threshold` | `10` | failures per client within the window that start a lockout |
| `bruteforce_lockout_base` | `60` | seconds of the first lockout, doubles with each further one |
| `bruteforce_lockout_max` | `3600` | seconds of the longest lockout |
| `bruteforce_account_threshold` | `20` | failures per username within the window that start the account throttle |
| `bruteforce_account_interval` | `5` | seconds between password checks while an account is throttled |
| `bruteforce_max_entries` | `100000` | size limit of the client table and of the account table |
| `body_read_idle_timeout` | `30` | seconds a request body may send nothing before it is aborted |
| `body_min_rate` | `1` | minimum average body rate in KB/s, `0` disables the check |
| `body_min_rate_grace` | `60` | seconds before `body_min_rate` is checked |
| `response_write_idle_timeout` | `30` | seconds a response may go unread before it is cut |
| `response_min_rate` | `1` | minimum average response rate in KB/s, `0` disables the check |
| `response_min_rate_grace` | `60` | seconds before `response_min_rate` is checked |

Every value is a plain number in one fixed unit, as the table says:
durations in whole seconds, sizes in KB and rates in KB/s (decimal, 1 KB =
1000 bytes, like the quota's GB). A commented example with every key is in
[`webdavgo.example.conf`](../cmd/webdavgo/webdavgo.example.conf).

## Settings page

**Admin → Settings** shows every key above in one of eight sections (Network &
listeners, TLS & domain, Connections & limits, Brute-force protection,
WebDAV, Users, Logging, Health), each with its saved value, a short description and its
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
  requests (up to `shutdown_timeout`) and closes. After moving the admin
  listener the page links to the new address, which is then the only one.
  In the TLS & domain section, `tls_mode = "acme"` works differently: Save
  and Apply both run the certificate request (see
  [Domain & certificate](installation.md#domain--certificate)), and the TLS values reach the
  file only once it has succeeded. `tls_mode = "off"` is saved at once. The
  domain and ACME fields are then disabled and not written.
  `read_header_timeout`, `idle_timeout`, `http2_max_concurrent_streams`,
  `max_connections`, `access_log`, `server_log`, `require_tls`, `cert_dir`
  and switching `tls_mode` back to `off` are marked "takes effect after
  service restart". The page lists every saved value still waiting for one.
- **Reset to defaults** (after a confirmation) writes the default of every
  editable key of the section into the file, in place. It takes effect like
  any saved change. In the TLS & domain section that includes the domain and
  ACME keys (`tls_mode = "off"`, `domain = ""`, `acme_ca = "production"`, …),
  and it clears the values of a failed certificate request. The running TLS
  state stays as it is until a service restart.

A field whose saved value differs from the running one says so, with the
running value. **Admin → Status** shows usage, connections and activity. The
certificate status is in the TLS & domain section.

## Timeouts

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
its slot after 30 s. Downloads at any speed above 1 KB/s are not affected.
On HTTP/2 connections at most `http2_max_concurrent_streams` requests run at
once per connection, so `max_connections` stays a meaningful bound.

## Listener defaults

| Listener   | Default port | Default listen address |
|------------|--------------|------------------------|
| WebDAV     | `8080`       | all interfaces         |
| Web Admin  | `8443`       | all interfaces         |

Change them with `webdav_port` / `webdav_listen_address` and `webgui_port` /
`webgui_listen_address` in the config file or via **Admin → Settings**, which saves them to the file. They take
effect with Apply on the Settings page or on the next restart. Connections
on the old listener finish their running requests. With
`tls_mode = "acme"` the WebDAV listener serves HTTPS only. The admin listener
always does.

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

## Per-client limits

A client is an IPv4 address or an IPv6 /64, as for the
[brute-force protection](administration.md#brute-force-protection).

- **Connections:** each client may hold `max_connections_per_ip` (32)
  connections per listener (WebDAV and admin are counted separately). A
  further connection is closed right after accept, before the TLS handshake
  and before any HTTP processing, and logged at Warn as `connection refused:
  per-IP limit` (`client`, `listener`, `limit`). A client is limited only
  while it holds all its connections. Closing one frees its place.
- **Requests without credentials:** WebDAV requests that carry no
  credentials (every one of them would be answered 401) pass a token bucket
  per client: `unauth_rate` (20) tokens per second, `unauth_burst` (50) at
  most. Without a token the request gets **429 with `Retry-After`** (seconds
  until the next token, at least 1) and nothing else happens. It is logged
  at Warn as `unauthenticated requests throttled` (`client`, `listener`,
  `rate`, `burst`). Requests with credentials are never counted or limited
  by this. The brute-force protection handles those.
- Both refusal lines are written at most once per client and limit per
  minute. The next line carries `suppressed=N`, the refusals not logged in
  between. Both limits clear themselves within seconds and have no manual
  unlock. **Admin → Security** lists the clients they held back, the
  Activity card counts them.
- Memory: the connection counts only hold clients with open connections
  (at most `max_connections` per listener). The token buckets and the table
  of rate-limited clients each hold at most `bruteforce_max_entries`
  clients. An idle bucket (full again) is dropped within a minute. When the
  bucket table is full, an idle entry is evicted first, otherwise the one
  used longest ago, and this is logged once at Warn.
