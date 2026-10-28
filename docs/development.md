# Development

## Build

```sh
go build -o webdavgo      # or: make build
make dist                 # static binaries for linux/amd64, linux/arm64 in dist/
make test                 # go vet, then test.sh
make clean
```

`make` stamps the version from `git describe` into the binary
(`-ldflags "-X main.version=…"`). It is logged in the `startup` line. A plain
`go build` reports `dev`. `make dist` builds with `CGO_ENABLED=0`, `-trimpath`
and `-s -w`.

Requires Go 1.26 or later. The dependencies are listed in
[`go.mod`](../go.mod), their licenses in
[THIRD_PARTY_LICENSES](../THIRD_PARTY_LICENSES).

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
program that test.sh builds once. It is not part of the server binary.
`oathtool` is not installed on macOS by default, and a separate
implementation also checks the server's. The server accepts each 30-second
step only once per admin, so test.sh uses the steps either side of the
current one and waits for the next step when it logs in more often than
that. A run takes up to a few minutes longer for it.

The ACME criteria (C98 to C103, C119) run against
[Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's ACME test
server, with `pebble-challtestsrv` as its DNS server (every name resolves to
127.0.0.1). Install both once:

```sh
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
```

test.sh finds them in `$(go env GOPATH)/bin` and Pebble's test certificates in
the Go module cache. Without them the ACME criteria fail. Pebble validates
TLS-ALPN-01 for real (no `PEBBLE_VA_ALWAYS_VALID`) by connecting to port 8080,
the test WebDAV listener. It also uses ports 14000, 15000, 8053 and 8055.
C98 is also the regression test for CertMagic's handling of our own
listener answering TLS-ALPN-01. Run it after every CertMagic update.

The Domain & certificate criteria (C137 to C140) restart Pebble so that it
validates on port **443**, where the page moves the WebDAV listener. macOS
lets unprivileged processes bind `:443`. On Linux, run with
`CAP_NET_BIND_SERVICE` or lower `net.ipv4.ip_unprivileged_port_start`.
