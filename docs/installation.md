# Installation

## Run

```sh
./webdavgo                               # /etc/webdavgo/webdavgo.conf, created with the defaults if missing
./webdavgo -config ./webdavgo.conf       # likewise created if missing
```

On first start, the console prints:

```
================================================================
  webdavgo: SETUP REQUIRED
================================================================

  No admin account exists yet. Create it in the admin UI.

  1. Open the admin UI in a browser:

       https://192.0.2.20:8443/
       https://[2001:db8::20]:8443/
       https://localhost:8443/

     The admin UI is listening on all interfaces (port 8443) …

  2. The browser warns that the certificate is self-signed.
     Continue only if it shows this SHA-256 fingerprint:

       83:27:50:…:AC:49

  3. Enter this setup token when the page asks for it:

       Token: <hex>

     Valid until 2026-10-29 10:23 UTC.
     For a new token run: sudo webdavgo setup-info

  Direct link with the token included:

       https://192.0.2.20:8443/setup?token=<hex>
       https://[2001:db8::20]:8443/setup?token=<hex>
       https://localhost:8443/setup?token=<hex>

================================================================
```

There is one URL per LAN address of the host (IPv4 first), plus `localhost`.
The line below them names the address the admin listener is actually bound
to (see [Admin access](administration.md#admin-access)). webdavgo cannot see
a firewall or router in front of the host, so it never claims that the port
is private. The expiry time is in UTC.

Open an admin URL, accept the self-signed certificate after comparing its
fingerprint (see [Admin access](administration.md#admin-access)), and enter
the token on the setup page. The direct links carry the token and skip that
step. Then create the admin account. Setup then
continues directly with the TOTP enrolment for that account. It is complete,
and WebDAV starts serving (503 until then), once a first code is confirmed and
the recovery codes have been shown. No restart is needed.

The token is stored in the database and survives a restart. `webdavgo
setup-info` prints the URLs again (with a new token once the old one has
expired).

On subsequent starts the setup wizard is skipped: the admin account already
exists in the database.

## Running as a service

On SIGINT or SIGTERM (Ctrl-C, `systemctl stop`) the server stops accepting
connections, lets in-flight requests finish for up to `shutdown_timeout`,
closes the database and exits 0. Requests still running after the timeout are
cut. The log states how many connections were closed, and the exit code is
still 0. An interrupted upload never replaces the old file and its temporary
file is removed. A second Ctrl-C during the grace period ends the process
immediately.

Leftover `.webdavgo-tmp-*` files from a process that was killed hard
(`kill -9`, OOM, power loss) are deleted at the next start, before the
listeners open. Each deleted file is logged at Warn.

## Deployment with `webdavgo install`

On Linux with systemd, one command sets up the service. Everything else
happens in the browser:

```sh
sudo ./webdavgo install
```

It prints its plan first, then:

1. copies the running binary to `/usr/local/bin/webdavgo` (temporary file +
   rename). Running `install` from a newer binary is the update path, and a
   running service is restarted to pick it up.
2. creates the system user and group `webdavgo` (no login shell, no home).
3. creates `/etc/webdavgo` and `/var/lib/webdavgo` (both webdavgo:webdavgo,
   0750). The service saves to its config file through a temporary file and a
   rename in that directory.
4. writes `/etc/webdavgo/webdavgo.conf` (webdavgo:webdavgo, 0640) **only if
   it does not exist**, from `webdavgo.example.conf` with
   `data_dir = "/var/lib/webdavgo"`, `require_tls = true`,
   `access_log = "/var/log/webdavgo/access.log"` and
   `server_log = "/var/log/webdavgo/webdavgo.log"` set. An existing
   `webdavgo.conf` is kept as it is (only owner and mode are enforced). If it
   does not set `access_log` or `server_log`, the plan says that their
   defaults apply, so the log files are written under `/var/log/webdavgo` all
   the same.
5. writes `/etc/systemd/system/webdavgo.service`, a hardened unit with
   `Type=notify` and `WatchdogSec=30s` (see
   [Health checks](administration.md#health-checks)): runs as
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
   (see [Log files](administration.md#log-files)).
6. writes `/etc/logrotate.d/webdavgo` (0644, see [Log files](administration.md#log-files)),
   also when logrotate is not installed, which the plan then points out.
7. runs `systemctl daemon-reload` and `systemctl enable --now webdavgo`.
8. prints where the admin listener is bound and how far it is reachable, the
   admin URLs and the admin certificate's SHA-256 fingerprint. While no
   admin exists, this is the setup block shown under [Run](#run), with the
   setup token on its own line and the setup URLs. Once an admin exists,
   the admin URLs are `https://<LAN address>:8443/admin/`. After an update that changes the database
   schema it first waits (up to two minutes, "Waiting for the service to
   migrate the database ...") until the restarted service has migrated it.

Running it again changes nothing that exists: data, config and the admin
certificate are kept. It refuses to run as non-root and on systems other than
Linux with systemd. `-root DIR` writes everything below `DIR` instead and skips
the user and systemctl steps (used by test.sh).

Then, in the browser: setup (admin account) → TOTP → **Domain &
certificate** → done.

**`webdavgo setup-info`** prints the same information again at any time
(`sudo webdavgo setup-info`). As root it
runs itself as the `webdavgo` user so that no root-owned database files
appear. The setup token lives in the database, valid for one hour. Once it
has expired, `setup-info` issues a new one that the running service accepts.
After setup it only says that setup is complete.

**`webdavgo uninstall`** stops and disables the service and removes the
unit, `/etc/logrotate.d/webdavgo` and the binary. It keeps `/etc/webdavgo`,
`/var/lib/webdavgo` and `/var/log/webdavgo` and says so. `-purge` also
removes all three and the system user, after you type the hostname (or with
`-yes`).

**`require_tls = true`** (set by `install`): as long as `tls_mode` is `off`,
the WebDAV listener is not started on a network address (logged at Warn).
Binding it to a loopback address (`webdav_listen_address = "127.0.0.1"`) is still allowed.
The admin listener runs as usual, so the Settings page can turn TLS on.

## Container

The image `joernfeuerabend/webdavgo` on Docker Hub (linux/amd64 and
linux/arm64) holds the release binary on a distroless base without a shell.
It runs as UID/GID 65532. Tags are the version (`0.1.0`), the minor
version (`0.1`) and `latest` for releases that are not prereleases.

```sh
docker run -d --name webdavgo \
  -p 443:443 -p 8443:8443 \
  -v webdavgo:/var/lib/webdavgo \
  --stop-timeout 35 \
  joernfeuerabend/webdavgo:0.1
```

With Compose:

```yaml
services:
  webdavgo:
    image: joernfeuerabend/webdavgo:0.1
    ports:
      - "443:443"
      - "8443:8443"
      # WebDAV over plain HTTP while tls_mode is "off".
      # - "8080:8080"
    volumes:
      - webdavgo:/var/lib/webdavgo
    stop_grace_period: 35s

volumes:
  webdavgo:
```

The volume `/var/lib/webdavgo` holds everything: the config file
(`/etc/webdavgo` is a symlink to it), the database, the users' files and
the certificates. Port 8080 serves WebDAV over plain HTTP as long as
`tls_mode` is `"off"`. Once **Domain & certificate** has obtained a
certificate, WebDAV moves to 443. Publish 8080 (`-p 8080:8080`) if you need
WebDAV before that. The stop timeout of 35 seconds leaves room for
`shutdown_timeout` (30 s by default). Docker's default of 10 seconds would
cut running requests.

**Internal use without TLS.** Without a domain setup, `tls_mode` stays
`"off"` and WebDAV is served on 8080 permanently:

```yaml
services:
  webdavgo:
    image: joernfeuerabend/webdavgo:0.1
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - webdavgo:/var/lib/webdavgo
    stop_grace_period: 35s

volumes:
  webdavgo:
```

WebDAV credentials then travel in clear text, so this fits only a trusted
network.

**Port 443** must be published as `443:443`. The certificate request uses
the TLS-ALPN-01 challenge, which the CA always sends to port 443, and
webdavgo answers it on its own port 443.

**First start.** The setup block (see [Run](#run)) is in
`docker logs webdavgo`. `docker exec webdavgo webdavgo setup-info` prints
it again, with a new token once the old one has expired. In a container,
step 1 of the block adds "In a container, use the host's address and the
published port instead.", and the line for a new token names the
`docker exec` command. The printed URLs show the container's addresses,
which are not reachable from outside the host. Open the admin UI at the
host's address instead, `https://<host>:8443/`. While no admin exists it
leads to the setup page, which asks for the token: copy it from the
`Token:` line. The page also lists the commands that show the token. Then
continue as in the [Quick start](../README.md#quick-start).

**Config file.** A new container creates the config file from
`webdavgo.example.conf` with `health_enabled = true`, `access_log = ""` and
`server_log = ""`. All logs go to stdout (`docker logs`, see
[Log files](administration.md#log-files)), and the image's `HEALTHCHECK`
runs `webdavgo healthcheck` against the health listener on 127.0.0.1:8082
inside the container (see [Health checks](administration.md#health-checks)).
An existing config file in the volume is never changed.

**Bind mount.** A host directory instead of the named volume
(`-v /srv/webdavgo:/var/lib/webdavgo`) must be writable by UID 65532:
`sudo chown 65532:65532 /srv/webdavgo`.

**Client IPs.** Brute-force protection and the per-client limits
(`max_connections_per_ip`, `unauth_rate`) use the source address of the
connection. Docker keeps it for IPv4. Without IPv6 enabled in the Docker
network, IPv6 clients arrive through docker-proxy with one shared address
and share one set of limits: one client's failed logins can lock out all
others. Enable IPv6 for the network the container uses, so that Docker
forwards IPv6 connections itself and keeps the client address. With
Compose:

```yaml
networks:
  default:
    enable_ipv6: true
```

With `docker run`, create a network with `docker network create --ipv6
webdavgo` and add `--network webdavgo`.

**Verify the signature.** Each image is signed with cosign in keyless mode
by the release workflow of `joernfeuerabend/webdavgo`:

```sh
VERSION=0.1.0
cosign verify joernfeuerabend/webdavgo:$VERSION \
  --certificate-identity "https://github.com/joernfeuerabend/webdavgo/.github/workflows/release.yml@refs/tags/v$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The image also carries a provenance attestation and an SBOM
(`docker buildx imagetools inspect joernfeuerabend/webdavgo:$VERSION`).

**Build the image locally** from a release archive (downloaded and verified
as in the [Quick start](../README.md#quick-start)). The Dockerfile does not
compile anything. It expects the binary at `linux/<arch>/webdavgo` and the
license files in the build context:

```sh
VERSION=0.1.0
ARCH=amd64
mkdir -p context/linux/$ARCH
tar -xzf webdavgo_${VERSION}_linux_$ARCH.tar.gz -C context/linux/$ARCH webdavgo
tar -xzf webdavgo_${VERSION}_linux_$ARCH.tar.gz -C context LICENSE THIRD_PARTY_LICENSES
curl -LO https://raw.githubusercontent.com/joernfeuerabend/webdavgo/v$VERSION/Dockerfile
docker build -f Dockerfile --build-arg VERSION=$VERSION -t webdavgo:$VERSION context
```

### Log files on the host (optional)

This is optional. By default a container logs to stdout, which
`docker logs` shows, and nothing below is needed for that. To keep the logs
as files on the host instead, mount an additional host directory for them.
It must be writable by UID 65532:

```sh
sudo install -d -o 65532 -g 65532 -m 0750 /srv/webdavgo-logs
docker run -d --name webdavgo \
  -p 443:443 -p 8443:8443 \
  -v webdavgo:/var/lib/webdavgo \
  -v /srv/webdavgo-logs:/var/log/webdavgo \
  --stop-timeout 35 \
  joernfeuerabend/webdavgo:0.1
```

With Compose, add the directory to `volumes`:

```yaml
    volumes:
      - webdavgo:/var/lib/webdavgo
      - /srv/webdavgo-logs:/var/log/webdavgo
```

Then set `access_log` and `server_log` to files in that directory, on the
Settings page (Logging) or in `webdavgo.conf` in the volume:

```toml
access_log = "/var/log/webdavgo/access.log"
server_log = "/var/log/webdavgo/webdavgo.log"
```

Save or Apply on the Settings page only writes the new paths to the config
file. They take effect after a restart of the container
(`docker restart webdavgo`), and until then the Settings page lists them
as waiting for a restart. After the restart, `docker logs` shows only a
copy of every Error record, which goes to stderr while `server_log` is set,
records from before the config file is read, and the setup block while no
admin exists. Everything else goes to the files, which webdavgo creates
with mode 0640.

There is no logrotate in the container. Rotate the files on the host, for
example with `/etc/logrotate.d/webdavgo-container`. After the rotation,
`docker kill -s USR1` makes webdavgo reopen its log files:

```
/srv/webdavgo-logs/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    create 0640 65532 65532
    sharedscripts
    postrotate
        docker kill -s USR1 webdavgo >/dev/null 2>&1 || true
    endscript
}
```

Replace `webdavgo` in `docker kill` with the container's name. Format and
contents of the files are described under
[Log files](administration.md#log-files).

## Domain & certificate

**Admin → Settings → TLS & domain** (the first setup leads there after the
recovery codes). Set `tls_mode` to `acme`, enter the domain and, optionally,
an e-mail address for the CA, then **Save** or **Apply**. Both run the
certificate request with the submitted values, whose progress page
(`/admin/domain`) shows it step by step. The config file must only hold a
consistent configuration, so nothing of it is written before the certificate
has been obtained:

1. **DNS:** the domain's A/AAAA records are listed. If none of them is an
   address of this host, that is a warning only (normal behind a NAT router).
   A name that does not resolve at all is an error (except with a custom
   `acme_ca`, which may resolve names its own way).
2. **Port 443:** webdavgo opens a TLS listener on `:443`. Errors explain
   "permission denied" (CAP_NET_BIND_SERVICE) and "already in use" (another
   web server). A behind-proxy mode is not supported yet.
3. **Trial order** at Let's Encrypt staging when `acme_ca = "production"`,
   to keep mistakes away from production rate limits. `acme_trial_ca`
   overrides or disables it, and a custom `acme_ca` gets none by default.
4. **Certificate** from `acme_ca`.
5. **Switch:** `tls_mode = "acme"`, `domain`, `acme_email`, `acme_ca`,
   `acme_trial_ca`, `acme_ca_root` and `webdav_port = 443` are saved to
   the config file in one write. The new TLS listener takes
   over and the old plaintext listener stops accepting connections and
   finishes its running requests (up to `shutdown_timeout`). No restart.

Failures are reported in plain English (for example "Port 443 is not
reachable from the internet" with a hint to check port forwarding, or "DNS
for … does not point to this server") with the CA's error in a details
element. The old listener keeps running
and nothing was saved: the config file is unchanged, and the TLS & domain
section shows the submitted values with the error, to correct and send
again. The **finish page** (`/admin/domain/done`) shows the certificate status
(issuer, expiry, next renewal or ARI window, last error) and the public
WebDAV URL `https://<domain>/`.

## Internet deployment

With `tls_mode = "acme"` webdavgo gets and renews its own certificate from an
ACME CA (Let's Encrypt by default) using the TLS-ALPN-01 challenge, which is
answered on the WebDAV listener itself. There is no plaintext WebDAV listener
then, so Basic Auth credentials only ever travel over TLS. With
`tls_mode = "off"` the server logs a Warn at startup that credentials are sent
in clear text: use it for development or on a trusted LAN only.

### Setup

The setup in the browser is described in the [Quick start](../README.md#quick-start).
It needs the same network preparation:

1. **DNS.** Create an A record (and AAAA, if the host has public IPv6) for
   the domain, pointing at your public address.
2. **Port forwarding.** Forward external TCP port **443** to the WebDAV
   listener (with a config file, set `webdav_port` to 443 or forward to the
   configured port). The CA always validates on port 443. Other external
   ports cannot work with TLS-ALPN-01.
3. **The admin port** (default 8443) needs no forwarding. Restrict it with
   `webgui_listen_address` or a firewall and use an SSH tunnel for remote
   administration (see [Admin access](administration.md#admin-access)).

Instead of [Settings → TLS & domain](#domain--certificate), the config file
can enable ACME. Start with the staging CA:

```toml
tls_mode   = "acme"
domain     = "dav.example.com"
acme_email = "admin@example.com"   # optional, for expiry notices
acme_ca    = "staging"             # first; see below
```

The server then obtains the certificate in the background and logs
`certificate obtained` or, at Error level, `certificate obtain failed`
(CertMagic retries with backoff). Once a staging certificate is obtained
(clients do not trust it yet), set `acme_ca = "production"` and restart.
Starting with staging keeps configuration mistakes away from Let's Encrypt's
production rate limits.

The listener speaks HTTP/1.1 and HTTP/2, TLS 1.2 minimum with Go's default
cipher suites, and sends
`Strict-Transport-Security: max-age=31536000; includeSubDomains` on every
response (no `preload`, and no OCSP stapling, as Let's Encrypt no longer
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
