#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jörn Feuerabend

# install.sh downloads the latest webdavgo release for this machine, verifies
# its checksum and runs "webdavgo install". Usage:
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/joernfeuerabend/webdavgo/main/install.sh)
#
# It checks the system first and changes nothing if a check fails. It asks
# before installing. All questions are read from /dev/tty, so the script
# also works when piped into bash. See docs/installation.md (Install script).

set -u
set -o pipefail

REPO=joernfeuerabend/webdavgo
SUMS_URL=https://github.com/$REPO/releases/latest/download/SHA256SUMS
DOCS_URL=https://github.com/$REPO/blob/main/docs/installation.md#install-script
BIN=/usr/local/bin/webdavgo
DATA=/var/lib
PORTS=(443 8443)
MIN_FREE_KB=$((100 * 1024))
WARN_FREE_KB=$((1024 * 1024))
WARN_MEM_KB=$((256 * 1024))

if [[ -t 1 && -z ${NO_COLOR+x} ]]; then
	GREEN=$'\e[32m' RED=$'\e[31m' YELLOW=$'\e[33m' BOLD=$'\e[1m' RESET=$'\e[0m'
else
	GREEN='' RED='' YELLOW='' BOLD='' RESET=''
fi

failed=0
arch=''
sums=''
tarball=''
version=''

pass() { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
fail() { printf '%s✗%s %s\n' "$RED" "$RESET" "$*"; failed=1; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# human prints a size given in KiB as MB or GB.
human() {
	if (($1 >= 1024 * 1024)); then
		printf '%d.%d GB' $(($1 / 1048576)) $(($1 % 1048576 * 10 / 1048576))
	else
		printf '%d MB' $(($1 / 1024))
	fi
}

# existing prints the path itself or its nearest existing parent directory.
existing() {
	local p=$1
	while [[ ! -e $p && $p != / ]]; do
		p=$(dirname -- "$p")
	done
	printf '%s\n' "$p"
}

# free_kb prints the free space in KiB on the filesystem holding $1.
free_kb() {
	df -Pk -- "$(existing "$1")" 2>/dev/null | awk 'NR == 2 { print $4 }'
}

check_system() {
	local os
	os=$(uname -s)
	if [[ $os != Linux ]]; then
		fail "Operating system: $os. webdavgo install needs Linux with systemd"
	elif ! have systemctl || [[ ! -d /run/systemd/system ]]; then
		fail "systemd not found (systemctl and /run/systemd/system are required)"
	else
		pass "Linux with systemd"
	fi
}

check_arch() {
	local m
	m=$(uname -m)
	case $m in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	armv6l | armv7l)
		fail "Architecture $m is not supported. A 64-bit OS (64-bit kernel) is required, e.g. 64-bit Raspberry Pi OS"
		return
		;;
	*)
		fail "Architecture $m is not supported. Releases exist for amd64 and arm64"
		return
		;;
	esac
	pass "Architecture $m ($arch)"
}

check_tools() {
	local tools=(curl tar sha256sum) missing=() t
	((EUID != 0)) && tools+=(sudo)
	for t in "${tools[@]}"; do
		have "$t" || missing+=("$t")
	done
	if ((${#missing[@]})); then
		fail "Missing tools: ${missing[*]}"
	else
		pass "Tools present: ${tools[*]}"
	fi
}

check_ports() {
	local listening port active=0
	if ! have ss; then
		warn "ss not found, port check skipped"
		return
	fi
	if have systemctl && systemctl is-active --quiet webdavgo 2>/dev/null; then
		active=1
	fi
	listening=$(ss -ltn 2>/dev/null | awk 'NR > 1 { n = split($4, a, ":"); print a[n] }')
	for port in "${PORTS[@]}"; do
		if ! grep -qx -- "$port" <<<"$listening"; then
			pass "Port $port is free"
		elif ((active)); then
			pass "Port $port is in use by the existing webdavgo installation"
		else
			fail "Port $port is in use by another program"
		fi
	done
}

check_disk() {
	local path kb
	for path in "${BIN%/*}" "$DATA"; do
		kb=$(free_kb "$path")
		if [[ -z $kb ]]; then
			warn "Free disk space on the filesystem of $path could not be determined"
		elif ((kb < MIN_FREE_KB)); then
			fail "Free disk space on the filesystem of $path: $(human "$kb"), at least 100 MB required"
		elif [[ $path == "$DATA" ]] && ((kb < WARN_FREE_KB)); then
			warn "Free disk space on the filesystem of $path: $(human "$kb"), less than 1 GB for data"
		else
			pass "Free disk space on the filesystem of $path: $(human "$kb")"
		fi
	done
}

check_memory() {
	local kb
	kb=$(awk '$1 == "MemTotal:" { print $2 }' /proc/meminfo 2>/dev/null)
	if [[ -z $kb ]]; then
		warn "Memory size could not be determined"
	elif ((kb < WARN_MEM_KB)); then
		warn "Memory: $(human "$kb"), less than 256 MB"
	else
		pass "Memory: $(human "$kb")"
	fi
}

check_existing() {
	if [[ -e $BIN ]]; then
		pass "Existing installation found at $BIN. webdavgo install will update it and keep data and configuration"
	else
		pass "No existing installation at $BIN"
	fi
}

check_github() {
	if ! have curl; then
		fail "GitHub not checked, curl is missing"
		return
	fi
	if ! sums=$(curl -fsSL --retry 2 -- "$SUMS_URL" 2>&1); then
		fail "GitHub not reachable: $SUMS_URL (${sums##*$'\n'})"
		sums=''
		return
	fi
	if [[ -z $arch ]]; then
		pass "GitHub reachable"
		return
	fi
	tarball=$(awk -v a="$arch" '$2 ~ "^webdavgo_[^_]+_linux_" a "\\.tar\\.gz$" { print $2; exit }' <<<"$sums")
	if [[ -z $tarball ]]; then
		fail "GitHub reachable, but the latest release has no tarball for $arch"
		return
	fi
	version=${tarball#webdavgo_}
	version=${version%%_*}
	pass "GitHub reachable, latest release v$version"
}

main() {
	if ! { : </dev/tty; } 2>/dev/null; then
		echo "This script needs a terminal to ask questions, but /dev/tty cannot be opened." >&2
		echo "Run it from an interactive shell, or see $DOCS_URL" >&2
		exit 1
	fi

	echo "${BOLD}Checking the system for webdavgo${RESET}"
	check_system
	check_arch
	check_tools
	check_ports
	check_disk
	check_memory
	check_existing
	check_github
	echo

	if ((failed)); then
		echo "A check failed. Nothing was changed."
		exit 1
	fi

	local url=https://github.com/$REPO/releases/download/v$version/$tarball
	local run=./webdavgo
	((EUID != 0)) && run="sudo ./webdavgo"
	cat <<EOF
${BOLD}Next steps${RESET}
  Version:      v$version
  Architecture: linux/$arch
  Download:     $url
  The download is verified against SHA256SUMS of the same release.

Then "$run install" runs. It copies the binary to
$BIN, creates the webdavgo user, /etc/webdavgo and
/var/lib/webdavgo, writes and starts the systemd service webdavgo and prints
the setup URL. An existing configuration and existing data are kept. It asks
whether to prepare the installation for updates via the web UI.
Details in docs/installation.md:
  $DOCS_URL

EOF

	local answer=''
	printf 'Install webdavgo v%s? [y/N] ' "$version"
	read -r answer </dev/tty || echo
	case ${answer,,} in
	y | yes) ;;
	*)
		echo "Aborted. Nothing was changed."
		exit 1
		;;
	esac

	tmp=$(mktemp -d) || exit 1
	trap 'rm -rf -- "$tmp"' EXIT
	cd -- "$tmp" || exit 1

	printf '%s\n' "$sums" >SHA256SUMS
	echo "Downloading $tarball"
	if ! curl -fsSL --retry 2 -o "$tarball" -- "$url"; then
		echo "${RED}Download failed.${RESET} Nothing was changed." >&2
		exit 1
	fi
	if ! sha256sum --ignore-missing -c SHA256SUMS; then
		echo "${RED}Checksum verification failed.${RESET} Nothing was changed." >&2
		exit 1
	fi
	if ! tar -xzf "$tarball" webdavgo; then
		echo "${RED}Extracting $tarball failed.${RESET} Nothing was changed." >&2
		exit 1
	fi
	echo

	local code=0
	if ((EUID == 0)); then
		./webdavgo install </dev/tty || code=$?
	else
		sudo ./webdavgo install </dev/tty || code=$?
	fi
	exit "$code"
}

main "$@"
