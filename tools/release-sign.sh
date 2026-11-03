#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jörn Feuerabend

# release-sign.sh signs webdavgo releases with minisign. The maintainer runs
# it locally, never in CI: the private keys and their passwords must not
# leave the maintainer's machine.
#
#   tools/release-sign.sh keygen [key-dir]
#       Creates the main and the reserve key pair, both protected by a
#       password that minisign asks for. The private keys go to key-dir
#       (default ~/.minisign), the public keys to cmd/webdavgo/keys, from
#       where the binary embeds them. Aborts if any of the keys exists.
#
#   tools/release-sign.sh sign vX.Y.Z[-rc.N] [main-secret-key]
#       Downloads the tarballs and SHA256SUMS of release vX.Y.Z or of a
#       pre-release such as vX.Y.Z-rc.N (also -alpha.N, -beta.N), rebuilds
#       the tag with "make dist" in a clean checkout and compares the
#       binaries. Only if they are identical it signs SHA256SUMS with the
#       main key (default ~/.minisign/webdavgo-main.key, minisign asks for
#       the password) and uploads SHA256SUMS.minisig to the release.
#
# The script never reads, stores or passes on a password. minisign asks
# for it on the terminal itself.

set -euo pipefail

repo=joernfeuerabend/webdavgo
top=$(cd "$(dirname "$0")/.." && pwd)
pubdir=$top/cmd/webdavgo/keys

die() {
    echo "release-sign.sh: $*" >&2
    exit 1
}

usage() {
    echo "usage: tools/release-sign.sh keygen [key-dir]" >&2
    echo "       tools/release-sign.sh sign vX.Y.Z[-rc.N] [main-secret-key]" >&2
    exit 2
}

need_tools() {
    local missing=()
    for t in minisign gh go git
    do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [[ ${#missing[@]} -gt 0 ]]
    then
        die "required tools not found: ${missing[*]} (this script needs minisign, gh, go and git)"
    fi
}

keygen() {
    local dir=${1:-$HOME/.minisign}
    if [[ "$dir" == "$top" || "$dir" == "$top"/* ]]
    then
        die "$dir is inside the repository, private keys must stay outside it"
    fi
    local name
    for name in main reserve
    do
        [[ ! -e "$dir/webdavgo-$name.key" ]] || die "$dir/webdavgo-$name.key exists already, nothing was changed"
        [[ ! -e "$pubdir/$name.pub" ]] || die "$pubdir/$name.pub exists already, nothing was changed"
    done
    mkdir -p "$dir"
    chmod 700 "$dir"
    for name in main reserve
    do
        echo "Creating the $name key pair. minisign asks for its password."
        # No -W: the private key is always protected by a password.
        minisign -G -p "$pubdir/$name.pub" -s "$dir/webdavgo-$name.key"
    done
    cat <<EOF

Done.
  Public keys:  $pubdir/main.pub and $pubdir/reserve.pub
                Commit them, the binary embeds them.
  Private keys: $dir/webdavgo-main.key and $dir/webdavgo-reserve.key

Back up BOTH private keys and their passwords offline now, for example on
two encrypted USB drives kept in different places. Keep the reserve key
offline. It is only needed if the main key is lost or compromised.
EOF
}

sign() {
    local tag=$1
    local key=${2:-$HOME/.minisign/webdavgo-main.key}
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.(0|[1-9][0-9]{0,8}))?$ ]] \
        || die "release tag $tag matches neither vMAJOR.MINOR.PATCH nor vMAJOR.MINOR.PATCH-(alpha|beta|rc).N"
    [[ -f "$key" ]] || die "secret key $key not found"
    [[ -f "$pubdir/main.pub" ]] || die "$pubdir/main.pub not found, run keygen first"
    local version=${tag#v}

    local work
    work=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" EXIT

    echo "Downloading the release assets of $tag"
    mkdir "$work/release"
    gh release download "$tag" -R "$repo" -D "$work/release" \
        -p "webdavgo_${version}_linux_amd64.tar.gz" \
        -p "webdavgo_${version}_linux_arm64.tar.gz" \
        -p SHA256SUMS
    if gh release view "$tag" -R "$repo" --json assets --jq '.assets[].name' | grep -qxF SHA256SUMS.minisig
    then
        die "$tag already has a SHA256SUMS.minisig asset"
    fi
    (cd "$work/release" && sha256sum -c SHA256SUMS) || die "the tarballs do not match SHA256SUMS"
    local listed
    listed=$(awk '{ print $2 }' "$work/release/SHA256SUMS" | sed 's/^\*//' | sort | tr '\n' ' ')
    [[ "$listed" == "webdavgo_${version}_linux_amd64.tar.gz webdavgo_${version}_linux_arm64.tar.gz " ]] \
        || die "SHA256SUMS lists unexpected files: $listed"

    echo "Rebuilding $tag in a clean checkout"
    git clone --quiet "https://github.com/$repo.git" "$work/src"
    git -C "$work/src" -c advice.detachedHead=false checkout --quiet "refs/tags/$tag"
    mkdir "$work/bin"
    local arch
    for arch in amd64 arm64
    do
        tar -xzf "$work/release/webdavgo_${version}_linux_$arch.tar.gz" -C "$work/bin" webdavgo
        mv "$work/bin/webdavgo" "$work/bin/webdavgo-$arch"
    done
    # The same Go release as CI, which the release binary names, and no
    # local Go settings that could change the build.
    local gover
    gover=$(go version "$work/bin/webdavgo-amd64" | awk '{ print $2 }')
    [[ "$gover" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "cannot read the Go version of the release binary: $gover"
    echo "Building with $gover"
    # VERSION as in CI: git describe could name another tag of the same
    # commit, such as vX.Y.Z-rc.2 for vX.Y.Z.
    (cd "$work/src" && env -u GOFLAGS -u GOAMD64 -u GOARM64 GOENV=off GOTOOLCHAIN="$gover" make dist VERSION="$tag")

    local mismatch=0
    for arch in amd64 arm64
    do
        if cmp -s "$work/bin/webdavgo-$arch" "$work/src/dist/webdavgo-$tag-linux-$arch"
        then
            echo "linux/$arch: identical"
        else
            echo "linux/$arch: DIFFERENT from the local build" >&2
            mismatch=1
        fi
    done
    [[ $mismatch -eq 0 ]] || die "the release binaries differ from the local build, nothing was signed"

    echo "Signing SHA256SUMS with $key. minisign asks for the password."
    minisign -S -s "$key" -m "$work/release/SHA256SUMS" -x "$work/release/SHA256SUMS.minisig"
    minisign -V -q -p "$pubdir/main.pub" -m "$work/release/SHA256SUMS" -x "$work/release/SHA256SUMS.minisig" \
        || die "the new signature does not verify against $pubdir/main.pub"

    gh release upload "$tag" -R "$repo" "$work/release/SHA256SUMS.minisig"
    echo "Uploaded SHA256SUMS.minisig to $tag."
}

[[ $# -ge 1 ]] || usage
need_tools
if [[ "$1" == keygen && $# -le 2 ]]
then
    keygen "${2:-}"
elif [[ "$1" == sign && $# -ge 2 && $# -le 3 ]]
then
    sign "$2" "${3:-}"
else
    usage
fi
