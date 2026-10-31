# Administration

## Admin access

The admin listener (default `:8443`) speaks **HTTPS only**, also on
localhost. Plain HTTP to that port gets a bare 400 and no page. TLS 1.2 is the
minimum.

- **Certificate.** On the first start webdavgo creates a self-signed ECDSA
  P-256 certificate, valid for 10 years, in `cert_dir`
  (`admin-selfsigned.crt`, key `admin-selfsigned.key` with mode 0600). Its
  names are `localhost`, `127.0.0.1`, `::1`, the hostname and every LAN
  address of the host at that time (link-local addresses excluded). It is
  only recreated when a file is missing, so the fingerprint stays the same
  across restarts. Delete both files and restart to get one with new
  addresses.
- **Fingerprint check.** The browser warns about the self-signed certificate.
  Compare the SHA-256 fingerprint it shows (certificate details) with the one
  in the setup banner or in the log line printed at every start:

  ```
  2026-10-27T17:09:00.512+01:00 INFO "admin certificate" sha256=83:27:50:…:AC:49 path=…/certs/admin-selfsigned.crt
  ```

  On the command line: `openssl x509 -in <cert_dir>/admin-selfsigned.crt -noout -fingerprint -sha256`.
- **With `tls_mode = "acme"`**, a browser that asks for the configured
  `domain` (TLS SNI) gets the ACME certificate and no warning. Access by IP
  address or `localhost` keeps the self-signed one.
- **Reachability.** By default (`:8443`) the admin listener binds all
  interfaces and is reachable from any network that can reach port 8443.
  On a VPS without a firewall, that is the internet. The startup log line
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

## Two-factor authentication (TOTP)

Every admin needs TOTP (RFC 6238: SHA-1, 6 digits, 30 s). Login is two steps:
username and password, then a code from the authenticator app. Until the
second step is done the session can only open the code page (or log out),
and it expires after 5 minutes.

- **Enrolment.** An admin without TOTP (the first admin during setup, a new
  admin, or after a reset) is sent to the
  enrolment page at the next login: QR code, the key in Base32 for manual
  entry and the `otpauth://` URI (issuer `webdavgo`, account
  `<username>@<domain or hostname>`). Enrolment is complete once one code is
  confirmed.
- **Recovery codes.** After enrolment, 10 recovery codes are shown **once**.
  Only their SHA-256 hashes are stored. Each one can be entered instead of a
  TOTP code, once.
- **Replay protection.** A code is accepted for the current 30-second step
  and one step either side, but a step is accepted only once per admin: the
  same code cannot be used for a second login.
- **Brute force.** Wrong TOTP and recovery codes count as failed logins for
  the client and the account, exactly like wrong passwords. While throttled,
  the code page answers 429.
- **Reset.** On **Admin → Users**, an admin can reset another admin's TOTP.
  That admin enrols again at the next login. Resetting your own TOTP needs a
  valid current code.

**Lost authenticator and recovery codes:** run on the server, with the same
`-config` / `-data-dir` as the service:

```sh
sudo -u webdavgo webdavgo reset-totp <username>
```

Plain `sudo webdavgo reset-totp …` works too: started as root on Linux, the
command runs itself again as the `webdavgo` user, so it never leaves
root-owned files (`-wal`, `-shm`) in the data directory.

It removes the TOTP secret and recovery codes of that user and nothing else
(no password change). The next login goes to the enrolment page. It also
raises that user's session epoch in the database, so the running service
ends all of that user's admin sessions at their next request (logged at
Warn: `admin session ended: sessions were revoked outside this process`).
It works without the HTTP listeners (the service may keep running) and exits
non-zero if the database cannot be opened or the user does not exist.

`reset-totp`, `setup-info` and `prune-props` never migrate the database schema. Only the
service does, at startup. If the database's schema version differs from the
binary's, they refuse. After an update, restart the service first so it
migrates the database. An older binary than the database gives the usual
"newer than binary target" error.

## Dead properties and `prune-props`

[Dead properties](clients.md#dead-properties) are stored in the database, in
the table `dead_props`, so a file backup alone does not contain them. Requests
through webdavgo keep the entries in step with the files. Files removed or
renamed outside webdavgo leave entries behind, which still count toward the
owner's quota. To delete the entries whose path no longer exists, run on the
server, with the same `-config` / `-data-dir` as the service:

```sh
sudo -u webdavgo webdavgo prune-props                 # everything
sudo -u webdavgo webdavgo prune-props alice/projects  # one directory
```

The directory is relative to `<data_dir>/users`, starting with the username, or an
absolute path below it. It need not exist any more. Only entries at or below it
are considered. The result is logged as `dead properties pruned` with `users`,
`paths` and `bytes`. The service may keep running. It sees the freed bytes in the
quota after its next restart, when it recounts usage.

A renamed file loses its properties when the entries are pruned, and a file
created later at a path that still has entries gets them back.

## Sessions, CSRF and headers

- The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict`. The
  session ID changes after the second factor.
- Every POST carries a per-session CSRF token (hidden form field, or the
  `X-CSRF-Token` header that HTMX sends, either one matching is enough). A
  missing or wrong token → 403, and the page shows the rejection. Forms that
  change the session (login, TOTP, enrolment, sign-out, setup) are full page
  loads, never HTMX-boosted, so the page always carries the current token.
  POSTs whose `Origin` (or `Referer`, or `Sec-Fetch-Site` for browsers that
  still send `Origin: null`) is not the admin listener itself → 403.
- All admin responses carry `Content-Security-Policy: default-src 'self'`
  (plus `img-src 'self' data:` for the QR code, no inline scripts or styles),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: same-origin` (browsers then send a real `Origin` on the
  UI's own POSTs, and nothing leaks to other sites). Pages also carry
  `Cache-Control: no-store`.
- All sessions of a user end when the user is deleted, the password is reset
  or the TOTP is reset (also by `reset-totp` from the shell). Every admin request also checks that the user still
  exists and still is an admin.

## Security page

**Admin → Security** shows the brute-force state (see
[Brute-force protection](#brute-force-protection)): clients that are locked
out or were before (source, locked until, remaining lockout, failures in the
window and in total, number of lockouts, last failure) and throttled
accounts (source, remaining throttle, failures in the window and in total,
next allowed check, last failure), most recent first. WebDAV user auth
(including `/api/v1/`), share tokens and the admin login (password, TOTP
and recovery codes) share one limiter. The source column counts each
entry's failures per path, e.g. `admin login: 3, share token: 1`. **Unlock** removes a client's lockout
and resets its doubling. **Clear** ends an account throttle. Both are logged
at Info with the acting admin. Useful when your own NAT address got locked
out by another device. No restart is needed.

A third table, **Rate-limited clients**, lists the clients held back by the
[per-client limits](configuration.md#per-client-limits): client, limit (connections per IP
or unauthenticated requests), listener, whether it is active, the remaining
time where there is one, refusals since the client was first recorded, and
the first and last refusal. A client is active while it holds all its
connections on a listener (no remaining time: it ends when a connection
closes) or has no token left, and for 60 s after a refusal. Listed are
clients active now or refused within the last 24 h, most recent first. The
table holds at most `bruteforce_max_entries` clients. When full, the one
refused longest ago among the inactive ones is dropped, and `+N not tracked`
says how many clients refused within 24 h were dropped or never recorded.
These limits clear themselves within seconds, so there is no unlock button.

## Authentication cache and request log

bcrypt (cost 12) takes about 180 ms per check on a current desktop CPU, and clients
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
the [unauthenticated rate limit](configuration.md#per-client-limits)), which are at Debug: on
a public server those are mostly scanners. They are counted on the Activity card instead (see
[Status: activity](#status-activity)). A 429 with credentials (brute-force
lockout or throttle) stays at Info. The admin listener writes a `request` line too,
at Debug only, with `listener=admin`, `method`, `path` (never the query
string), `client`, `status` and `duration`.

`client` is the full remote IP (also for IPv6, where the brute-force
protection groups by /64).

`auth` is `cache`, `bcrypt`, `token` (share), `blocked` (429 from the
brute-force protection, no password check) or `none` (no credentials).
`auth_ms` is the time spent authenticating and is included in `duration`.

Authentication problems on the WebDAV listener get an extra Warn line next
to the `request` line. No password, token or code is ever logged.

| Message | When | Fields |
|---|---|---|
| `webdav auth failed` | user Basic Auth (WebDAV or `/api/v1/`) with credentials that failed the password check | `username` (as attempted), `client`, `method`, `path` |
| `share auth failure` | unknown share ID, or wrong recipient email or token (the line does not say which, like the 401). No line without credentials or with an empty share ID | `share_id`, `claimed_email` (both cut to 64 bytes), `client` |
| `share token expired` | correct share credentials after `expires_at` (401, not counted as a failure) | `share_id` (cut to 64 bytes), `client` |
| `auth refused: throttled` | 429 because the client is locked out or the account is throttled | `client`, `source` (`WebDAV user auth` or `share token`), `username` (user auth only), `scope` (`client` or `account`), `retry_after` |

Requests without credentials (`auth=none`, the normal 401 challenge) get no
extra line.

Errors that x/net/webdav reports for a request (`webdav internal error`,
`share webdav error`, with `status` and `err`) are at Warn for a 5xx and
for a fault of the local storage whatever the status (`ENOSPC`, `EDQUOT`,
`EIO`, `EROFS`, `EACCES`, `EPERM`). x/net answers e.g. a PUT on a full disk
with 405. Other client errors such as MKCOL on an existing collection (405)
or a missing file (404) are at Debug.

## Log files

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

The paths come from `access_log` and `server_log`. The defaults above apply
when the config does not set them. An empty value (`""`) sends those records
to stdout instead. A missing log directory is created (0750) before the
files are opened. If that fails, the server exits with an error naming the
directory and the reason. Only the server writes the files: `setup-info`,
`reset-totp`, `prune-props`, `install` and `uninstall` always log to the terminal.

**journald still matters.** Records from before the config is loaded, and,
with `server_log` set, a copy of every Error record go to stdout/stderr and so
to the journal, which is why a failed start shows in `systemctl status
webdavgo` and `journalctl -u webdavgo`. A log file that cannot be opened is
reported there too, and the service does not start (no silent fallback to
stdout).

**Rotation** is done by logrotate with `/etc/logrotate.d/webdavgo`: daily,
14 files kept, compressed from the second rotation on (`delaycompress`),
empty files skipped. After moving the files, logrotate runs
`systemctl kill -s USR1 webdavgo.service`. On SIGUSR1 webdavgo opens new
files at the configured paths, switches to them and then closes the old
ones, so no record is lost, and logs `log files reopened`. If a new file
cannot be opened, it keeps writing to the old one and logs a Warn. To rotate
by hand: `sudo logrotate -f /etc/logrotate.d/webdavgo`.

## Brute-force protection

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
  checked without bcrypt). Wrong tokens count toward the client. During its
  lockout they get 429 instead of 401.
- **Per account:** after `bruteforce_account_threshold` failures for one
  username within the window, from any number of clients, only one password
  check per `bruteforce_account_interval` runs for it. Other uncached
  attempts get 429 with `Retry-After`. Accounts are never locked hard, which
  would let anyone lock out the real user.
- Unknown usernames are checked against a dummy bcrypt hash, so they take as
  long as wrong passwords for existing users and do not reveal which
  usernames exist.
- Requests without credentials still get the normal 401 challenge (429
  beyond `unauth_rate`, see [Per-client limits](configuration.md#per-client-limits)).
- Lockouts and account throttles are logged at Warn with the client or
  username, the failure count and the duration. Every request refused with
  429 is logged at Warn: `auth refused: throttled` on the WebDAV listener,
  `login refused: throttled` on the admin listener. All state is in memory,
  bounded to `bruteforce_max_entries` (100 000) clients and as many
  usernames, and is reset by a restart. When a table is full, a locked-out
  client or a throttled account is never dropped to make room (that would let
  an attacker end their own lockout by flooding the table). The account
  table drops the one seen longest ago among the others. **Admin → Security** shows it and can unlock clients and accounts.

## Status: connections

**Admin → Status** lists the open connections on both listeners (`webdav`
and `admin`), refreshed every 2 s while the page is open: remote IP,
protocol (HTTP/1.1 or HTTP/2, known after the first request), connected
since, identity (username, `share <id>` for `/s/<id>`, an admin's name, or
`unauthenticated`), the running requests (method and path, for HTTP/2 every
active stream), bytes received and sent on the wire (TLS included) and the
transfer rate since the previous refresh. Query strings are never shown. A
connection leaves the list when it closes.

The polling requests (`/admin/status/connections`, `/admin/status/activity`,
`/admin/logs/entries`) need a valid admin session but do not extend its 24 h sliding expiry, so a
tab left open does not keep the session alive. When the session has ended, the
poll answers with `HX-Redirect` and the browser goes to the login page.

## Status: activity

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
  credentials (their `request` lines are at Debug). The admin listener never
  answers 401
- bytes received and sent on the wire (TLS included, as in the connections
  table)
- TLS handshake errors (the `TLS handshake error` messages of Go's HTTP
  server, counted even when `log_level` hides them)

Authentication:

- failed attempts by source: WebDAV user (WebDAV and `/api/v1/`), share
  token, admin password, admin second factor (TOTP, recovery code and the
  code for resetting one's own TOTP). A failed attempt is a credential that
  was checked and was wrong. Requests without credentials, requests refused
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

- **Client lockouts:** clients locked out now, clients with a lockout that
  started or a request refused, lockouts started, and requests refused with
  429 because the client is locked out (all listeners).
- **Account throttles:** accounts throttled now, accounts with a throttle
  that engaged or a request refused, throttles engaged, and requests refused
  with 429 because the account is throttled (all listeners).
- **Per-IP connection limit:** clients active now (holding all their
  connections on a listener, or refused within the last 60 s), clients with
  a refused connection, and connections refused, per listener (webdav · admin).
- **Unauthenticated rate limit:** clients active now (no token left, or
  refused within the last 60 s), clients with a refused request, and requests
  refused with 429.

Below, a bar per clock hour (UTC) of the last 24 h shows the failed
attempts stacked by source. Hovering a bar shows the exact numbers. Two top
lists show the five client IPs and the five attempted usernames (WebDAV user
and admin) with the most failed attempts in the last 24 h, with the sources
involved. A username is marked `exists` or `unknown` from the user table at
the time the card is rendered. A third top list shows the five client IPs
with the most unauthenticated 401s in the last 24 h.

Counters are kept in 5-minute slots (288 for 24 h), so "last hour" covers
55 to 60 minutes and "last 24 h" 23 h 55 min to 24 h. Top lists and distinct
counts are kept per clock hour (24 buckets) and remember when each key was
last seen, so distinct counts cover exactly the last hour and 24 h, while
the top lists cover the current and the 23 previous clock hours. Each hourly
table holds at most 1000 keys (client IPs, usernames, users, shares,
clients with unauthenticated 401s, and the clients or accounts per
automatic limit). Beyond that, a top list shows `+N not tracked` and a
distinct count is prefixed with `≥`. Usernames are stored with at most 64
bytes. The peak of open connections from a single client is recorded when a
client opens a connection. Connections held since an earlier period count
from the client's current number.

## Live Log page

**Admin → Live Log** shows the newest log records of the running process
(`log_buffer_entries`, default 2000), newest first, with a minimum-level
filter, a case-insensitive text filter and optional auto-refresh every 2 s.
At most the newest 500 matching records are shown. The buffer gets a copy of every record that goes to stdout/journald or to the
[log files](#log-files). It is lost on restart, the log is not. Each buffered record keeps at most 256 bytes of
message and 1024 bytes of attributes, cut at a UTF-8 boundary and marked
`…(+N bytes)`. The journal or log file keeps the full line. Admin logins are logged with username and
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

## Health checks

The health listener serves `/livez` and `/readyz` for container runtimes,
load balancers and `webdavgo healthcheck`. It is off by default. Set
`health_enabled = true` to start it on `health_bind` (default
`"127.0.0.1"`) and `health_port` (default `8082`), in the config file or in
the **Health** section of **Admin → Settings**. Apply moves it without a
restart: the old listener stops first, then the new one starts. If the new
one cannot bind, the old one is restored and the page reports the error.
Turning it off is logged at Info as `health listener stopped`. If it cannot
bind at startup, the server exits with `health listener failed`.

The listener speaks plain HTTP and has no authentication, so keep it on
`127.0.0.1` unless something outside the host must reach it. Its responses
carry only `ok` or a short reason, never paths, versions or error details.
`health_port` must be between 1 and 65535 and, while the listener is
enabled, differ from `webdav_port` and `webgui_port` (by port alone,
whatever the addresses). `health_bind` is empty (all interfaces) or a host
name or IP address without port.

| Path | 200 `ok` when | Otherwise |
|------|---------------|-----------|
| `/livez` | the admin listener runs and no listener has failed | 503 `not serving` |
| `/readyz` | a probe file (`.readyz-*`) can be created, written and deleted in `data_dir`, and the database answers a ping within 2 s | 503 `data directory not writable` or `database unreachable`, with the details logged at Warn |

Only GET and HEAD are allowed (others get 405 with `Allow: GET, HEAD`).
Every other path gets 404, and every response carries
`Cache-Control: no-store`. Each probe is logged at Debug as a `request` line
with `listener=health`, `path`, `client` and `ok`. The listener accepts at
most 8 connections at a time, separately from `max_connections`, and its
probes do not appear on the Status page. A client gets 5 s to send the
headers (at most 8 KiB) and 10 s each for reading the request and writing
the response. Idle connections close after 60 s.

**`webdavgo healthcheck [-config <path>]`** sends `GET /readyz` to the
health listener named in the config file and exits 0 on 200, otherwise 1. It
reads the config file and nothing else (no database, no data directory, no
log files) and never creates the file. A wildcard `health_bind` (`""` or
`0.0.0.0`) is reached at `127.0.0.1`, `::` at `::1`. Proxy variables from the
environment are ignored and the request times out after 3 s. On failure it
prints one line to stderr, for example `healthcheck: 503 Service Unavailable:
database unreachable`. With `health_enabled = false` it exits 1 with
`healthcheck: health listener disabled in config`.

**systemd watchdog.** Independent of the health listener, the server
reports `READY=1` to systemd once its listeners serve. The unit written by
`webdavgo install` sets `Type=notify` and `WatchdogSec=30s`. The server then
pings the watchdog every half interval, but only while the `/livez` check
passes, so systemd restarts a process that is no longer live. A skipped ping
is logged at Warn.

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
[Two-factor authentication](#two-factor-authentication-totp). For your own
client locked out by the brute-force protection, restart the server (the
state is in memory) or unlock it on **Admin → Security** from another
address.
