<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 Jörn Feuerabend -->
# Release signing keys

This directory holds the minisign public keys that the webdavgo binary
embeds (see `minisign.go`) to verify updates offered on the admin UI's
Update page:

- `main.pub` signs every release.
- `reserve.pub` is accepted as well and takes over if the main key is lost
  or compromised.

`tools/release-sign.sh keygen` creates both key pairs and writes the public
keys here. The private keys never belong in this repository. A build without
these files cannot verify, and therefore never offers, any update.
