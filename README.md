# webdavgo

webdavgo is a WebDAV file server in a single Go binary. It supports
WebDAV SEARCH (RFC 5323) and includes what is needed to run it directly
on the internet.

## Why

- **One function:** webdavgo serves files over WebDAV.
- **WebDAV compliant:** Passes the [litmus](http://www.webdav.org/neon/litmus/)
  WebDAV compliance suite with 100 % in all test suites (basic, copymove,
  props, locks, http).
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

To get a server running, see [Quick start](#quick-start).

## Screenshots

![Admin dashboard](docs/screenshots/dashboard.png)
![Status page](docs/screenshots/status.png)

## Features

**WebDAV & sync**
- WebDAV SEARCH (RFC 5323) with the basicsearch grammar: `and`, `or`,
  `not`, comparisons, `like`, `contains`, `orderby` and `limit`
- Conditional requests (`If-Match`, `If-None-Match`), atomic PUT and
  consistent ETags
- Dead properties (PROPPATCH) stored in the database
- Standard WebDAV without client-specific extensions

**Users & sharing**
- Multiple users, each with an isolated data directory and a storage quota
- Invite external recipients to a folder by email, without creating an
  account for them. Invites are created through a REST API
  (`/api/v1/shares`), the only part of webdavgo outside the WebDAV
  standard. Recipients then use plain WebDAV, including SEARCH

**Security features**
- Automatic TLS certificates via Let's Encrypt (ACME)
- Brute-force protection on all login paths
- Limits on slow request bodies
- Admin UI over HTTPS only, with TOTP two-factor authentication and
  CSRF protection

**Operation**
- First-run setup wizard with a one-time token
- `webdavgo install` sets the server up as a system service
- Web admin UI for users, shares, connections, activity and a live log
- Files are stored as plain files in the data directory and can be backed
  up with standard tools

## Quick start

You need:

- a Linux server with systemd (amd64 or arm64) and root access,
- a domain whose A record (and AAAA record for IPv6) points to the server,
- port 443 reachable from the internet. Behind a NAT router, forward TCP
  port 443 to the server. Let's Encrypt validates the domain on this port.

**1. Download and verify the latest release** (version and architecture
from the [Releases](https://github.com/joernfeuerabend/webdavgo/releases) page):

```sh
VERSION=0.1.0
ARCH=amd64
curl -LO https://github.com/joernfeuerabend/webdavgo/releases/download/v$VERSION/webdavgo_${VERSION}_linux_$ARCH.tar.gz
curl -LO https://github.com/joernfeuerabend/webdavgo/releases/download/v$VERSION/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf webdavgo_${VERSION}_linux_$ARCH.tar.gz
```

**2. Install it as a service:**

```sh
sudo ./webdavgo install
```

This copies the binary to `/usr/local/bin`, creates the `webdavgo` user,
`/etc/webdavgo` and `/var/lib/webdavgo`, and starts the systemd service.
At the end it prints a setup URL with a one-time token and the fingerprint
of the admin certificate.

**Alternative to steps 1 and 2:** the install script does both in one
command:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/joernfeuerabend/webdavgo/main/install.sh)
```

It checks systemd, architecture, free ports, disk space and the connection
to GitHub, shows the version it will install and asks before it changes
anything. Then it downloads and verifies the release and runs
`sudo ./webdavgo install`. See [Install script](docs/installation.md#install-script).

**3. Create the admin account.** Open the setup URL in a browser. The
browser warns about a self-signed certificate: continue only if it shows
the printed fingerprint. Create the admin account, enroll an authenticator
app and store the recovery codes. This account is for the admin UI only.

**4. Get the certificate.** Setup continues with **Domain & certificate**.
Enter your domain and select **Apply**. webdavgo checks DNS and port 443,
obtains a Let's Encrypt certificate and serves WebDAV at
`https://<your-domain>/`. No restart is needed.

**5. Add users** under **Admin → Users** and connect a WebDAV client to
`https://<your-domain>/`. The password field holds a random suggestion
(four groups of five characters, the dashes belong to the password), and
**New suggestion** generates another one. The eye button next to it hides
the password while the screen is shared. An admin account cannot use WebDAV
or the share API, not even with the correct password. If you administer the
server and also want to sync files, create a second account with role user,
for example `alice` for WebDAV next to `alice-admin` for the admin UI. See
[Users and roles](docs/administration.md#users-and-roles).

**6. Uninstall.** `sudo webdavgo uninstall` removes the service and
`sudo webdavgo uninstall -purge` also removes data, configuration and logs.
See [Uninstall](docs/installation.md#uninstall).

The admin UI listens on port 8443 on all interfaces, so on a server
without a firewall it is reachable from the internet. To keep it private,
block port 8443 in the firewall and open it through an SSH tunnel:
`ssh -N -L 8443:localhost:8443 user@your-server`, then use the
`https://localhost:8443/...` setup URL.

Setup token expired? `sudo webdavgo setup-info` prints a new one. To
update, download a newer release and run `sudo ./webdavgo install` again.
Data and configuration are kept.

To run webdavgo with Docker instead, see [Container](docs/installation.md#container).

## Documentation

- [Installation](docs/installation.md): first start, `webdavgo install`, domain and certificate, internet deployment
- [Configuration](docs/configuration.md): config file, all keys, Settings page, request limits
- [Administration](docs/administration.md): admin access and TOTP, Security, Status and Live Log pages, log files, brute-force protection, emergency recovery
- [Clients](docs/clients.md): SEARCH, ETags and conditional requests, hrefs, storage quota
- [Shares](docs/shares.md): email-bound shares and the share API
- [Development](docs/development.md): build and tests

## License

Copyright (C) 2026 Jörn Feuerabend

This program is licensed under the GNU Affero General Public License,
version 3 only (AGPL-3.0-only). See [LICENSE](LICENSE).

A commercial license is available for use cases where the AGPL
obligations are not acceptable. Contact licensing@webdavgo.com.

Contributions require signing the Contributor License Agreement. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Third-party components and their licenses are listed in
[THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
