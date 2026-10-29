# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jörn Feuerabend

# webdavgo build targets. Release pipelines are out of scope here.

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64

.PHONY: build dist test clean licenses

# build: for the current OS and architecture.
build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o webdavgo ./cmd/webdavgo

# dist: static, stripped binaries for every platform into dist/, with the
# license files every distributed binary must be accompanied by.
dist:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "dist/webdavgo-$(VERSION)-$$os-$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/webdavgo-$(VERSION)-$$os-$$arch ./cmd/webdavgo || exit 1; \
	done
	cp LICENSE THIRD_PARTY_LICENSES dist/

# SPDX identifiers of everything a dist binary contains: the Go standard
# library ("std"), each module of the build graph, and htmx. "make licenses"
# stops at a module missing here, so a new dependency is classified, and
# checked against AGPL-3.0-only, on purpose rather than by default.
define LICENSE_SPDX
std BSD-3-Clause
github.com/BurntSushi/toml MIT
github.com/caddyserver/certmagic Apache-2.0
github.com/caddyserver/zerossl MIT
github.com/dustin/go-humanize MIT
github.com/google/uuid BSD-3-Clause
github.com/klauspost/cpuid/v2 MIT
github.com/libdns/libdns MIT
github.com/mholt/acmez/v3 Apache-2.0
github.com/miekg/dns BSD-3-Clause
github.com/remyoudompheng/bigfft BSD-3-Clause
github.com/zeebo/blake3 CC0-1.0
go.uber.org/multierr MIT
go.uber.org/zap MIT
go.uber.org/zap/exp MIT
golang.org/x/crypto BSD-3-Clause
golang.org/x/net BSD-3-Clause
golang.org/x/sys BSD-3-Clause
golang.org/x/text BSD-3-Clause
modernc.org/libc BSD-3-Clause AND MIT
modernc.org/mathutil BSD-3-Clause
modernc.org/memory BSD-3-Clause
modernc.org/sqlite BSD-3-Clause AND LicenseRef-SQLite-Public-Domain
rsc.io/qr BSD-3-Clause
htmx.org 0BSD
endef
export LICENSE_SPDX

# Prints the copyright and license notices in the source files given after
# the nlic license files that the component's license files do not already
# carry, each comment block once with the files it appears in. A block
# counts as covered when every "Copyright <year>|The ..." holder in it
# appears in the license files; a block without such a line is printed only
# if it grants permissions itself (public-domain remarks are not notices).
define LICENSE_NOTICES_AWK
function holder(l,   h) {
	h = l; sub(/.*Copyright[ ]*(\([cC]\)|©)?[ ]*/, "", h); sub(/^[0-9 ,-]+/, "", h)
	sub(/[.,].*/, "", h); sub(/[ \t]+$$/, "", h); return h
}
function flush(   n, i, ls, own, nh, h) {
	if (blk == "") return
	if (blk ~ /[Cc]opyright|COPYRIGHT|[Ll]icen[cs]e|LICEN[CS]E/) {
		n = split(blk, ls, "\n"); own = 1; nh = 0
		for (i = 1; i <= n; i++)
			if (ls[i] ~ /Copyright[ ]*(\([cC]\)|©)?[ ]*([0-9]|The )/) {
				nh++; h = holder(ls[i])
				if (h == "" || index(lic, h) == 0) own = 0
			}
		if (nh == 0) own = (blk !~ /[Pp]ermission is|Licensed under|License as published/)
		if (!own) {
			if (!(blk in seen)) { order[++m] = blk; seen[blk] = "" }
			if (index(" " seen[blk] ",", " " path ",") == 0)
				seen[blk] = seen[blk] (seen[blk] == "" ? "" : ", ") path
		}
	}
	blk = ""; mode = ""
}
FNR == 1 { flush(); fi++; path = FILENAME; if (index(path, root) == 1) path = substr(path, length(root) + 1) }
fi <= nlic { lic = lic $$0 "\n"; next }
mode == "c" { blk = blk "\n" $$0; if ($$0 ~ /\*\//) flush(); next }
/^[ \t]*\/\// { if (mode != "l") { flush(); mode = "l"; blk = $$0 } else blk = blk "\n" $$0; next }
{ flush() }
/^[ \t]*\/\*/ { mode = "c"; blk = $$0; if (substr($$0, index($$0, "/*") + 2) ~ /\*\//) flush() }
END { flush(); for (i = 1; i <= m; i++) printf "%s\nNotice in: %s\n%s\n\n%s\n", thin, seen[order[i]], thin, order[i] }
endef
export LICENSE_NOTICES_AWK

# licenses: regenerate THIRD_PARTY_LICENSES, offline. License texts are
# copied verbatim: the Go distribution's LICENSE and PATENTS, every
# LICENSE*, COPYING*, NOTICE*, PATENTS* and *-LICENSE file at the root of
# each module linked into a dist binary (from the module cache, so run
# "go mod download" first), and third_party/htmx/LICENSE for the embedded
# cmd/webdavgo/assets/htmx.min.js, which carries none; replace that file
# when htmx is updated. Below each component follow the notices
# LICENSE_NOTICES_AWK finds in its Go and assembly files compiled into a
# dist binary. LC_ALL=C makes sort and awk order the components the same
# way in every locale.
licenses:
	@set -e; export LC_ALL=C; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	for p in $(PLATFORMS); do \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go list -deps \
			-f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/webdavgo \
			| sort -u | sed "s|\$$| $$p|"; \
	done | sort > "$$tmp/deps"; \
	for p in $(PLATFORMS); do \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go list -deps \
			-f '{{$$d := .Dir}}{{range .GoFiles}}{{$$d}}/{{.}}{{"\n"}}{{end}}{{range .SFiles}}{{$$d}}/{{.}}{{"\n"}}{{end}}' ./cmd/webdavgo; \
	done | grep . | sort -u > "$$tmp/files"; \
	awk -v n=$(words $(PLATFORMS)) '{ k = $$1 " " $$2 " " $$3; if (!(k in c)) o[++m] = k; \
		c[k]++; p[k] = p[k] (p[k] == "" ? "" : ", ") $$4 } \
		END { for (i = 1; i <= m; i++) print o[i], (c[o[i]] == n ? "all" : p[o[i]]) }' \
		"$$tmp/deps" > "$$tmp/mods"; \
	spdx() { s=$$(printf '%s\n' "$$LICENSE_SPDX" | awk -v m="$$1" '$$1 == m { sub(/^[^ ]+ /, ""); print }'); \
		[ -n "$$s" ] || { echo "licenses: no SPDX entry for $$1 in the Makefile's LICENSE_SPDX" >&2; exit 1; }; \
		echo "$$s"; }; \
	goroot=$$(go env GOROOT); mkdir "$$tmp/go"; \
	for f in LICENSE PATENTS; do \
		for d in "$$goroot" "$$(dirname "$$goroot")"; do \
			if [ -f "$$d/$$f" ]; then cp "$$d/$$f" "$$tmp/go/"; break; fi; \
		done; \
	done; \
	[ -f "$$tmp/go/LICENSE" ] || { echo "licenses: no LICENSE in $$goroot or its parent" >&2; exit 1; }; \
	htmx=$$(grep -oE 'version:"[^"]+"' cmd/webdavgo/assets/htmx.min.js | cut -d'"' -f2); \
	[ -f third_party/htmx/LICENSE ] || { echo "licenses: third_party/htmx/LICENSE missing" >&2; exit 1; }; \
	rule=$$(printf '%080d' 0 | tr 0 =); thin=$$(printf '%080d' 0 | tr 0 -); \
	entry() { s=$$(spdx "$$3") || exit 1; \
		printf '\n%s\nComponent: %s\nVersion:   %s\nSPDX:      %s\nPlatforms: %s\nSource:    %s\n' \
			"$$rule" "$$1" "$$2" "$$s" "$$4" "$$5"; \
		lics=""; nl=0; \
		for f in $$(ls "$$6" | grep -iE '^([a-z0-9]+-)?(licen[cs]e|copying|notice|patents)' | grep -v '\.go$$'); do \
			[ -f "$$6/$$f" ] || continue; lics="$$lics $$6/$$f"; nl=$$((nl + 1)); \
			printf '%s\nFile: %s\n%s\n\n' "$$thin" "$$f" "$$thin"; cat "$$6/$$f"; \
		done; \
		[ -n "$$7" ] || return 0; \
		srcs=$$(awk -v d="$$7/" 'index($$0, d) == 1' "$$tmp/files"); \
		[ -n "$$srcs" ] || return 0; \
		awk -v nlic=$$nl -v root="$$7/" -v thin="$$thin" "$$LICENSE_NOTICES_AWK" $$lics $$srcs; }; \
	{ \
		printf '%s\n' "Third-party software in webdavgo" "================================" "" \
			"The webdavgo release binaries statically link the Go standard library and" \
			"the Go modules listed below, and embed htmx (assets/htmx.min.js). For each" \
			"component this file gives its version, SPDX license identifier, the" \
			"platforms whose binaries contain it, and the complete text of its license" \
			"files as the component ships them. After them follow, verbatim and with" \
			"the files they appear in, the copyright and license notices in the" \
			"component's compiled source files that its license files do not already" \
			"carry." "" \
			"Generated by \"make licenses\"; do not edit by hand." "" "Components:"; \
		printf '  %-40s %s\n' "Go standard library and runtime" "$$(go env GOVERSION)"; \
		while read path ver dir plat; do printf '  %-40s %s\n' "$$path" "$$ver"; done < "$$tmp/mods"; \
		printf '  %-40s %s\n' "htmx (assets/htmx.min.js)" "$$htmx"; \
		entry "Go standard library and runtime" "$$(go env GOVERSION)" std all "https://go.dev" \
			"$$tmp/go" "$$goroot/src"; \
		while read path ver dir plat; do \
			entry "$$path" "$$ver" "$$path" "$$plat" "Go module $$path@$$ver" "$$dir" "$$dir"; \
		done < "$$tmp/mods"; \
		entry "htmx (assets/htmx.min.js)" "$$htmx" htmx.org all \
			"https://github.com/bigskysoftware/htmx/tree/v$$htmx" third_party/htmx; \
	} > "$$tmp/out"; \
	mv "$$tmp/out" THIRD_PARTY_LICENSES; \
	echo "THIRD_PARTY_LICENSES: $$(($$(wc -l < "$$tmp/mods") + 2)) components"

# test: static checks, then the integration criteria (see README, Test).
test:
	go vet ./...
	./test.sh

clean:
	rm -rf dist webdavgo
