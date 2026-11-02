// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// minisign.go verifies minisign signatures (Ed25519), the format the
// release signing script (tools/release-sign.sh) produces for SHA256SUMS.
// Both signature algorithms are supported: the legacy one ("Ed"), which
// signs the file itself, and the prehashed one ("ED"), which signs the
// BLAKE2b-512 hash of the file. The global signature over the signature and
// the trusted comment is checked as well.
//
// File formats (see https://jedisct1.github.io/minisign/):
//
//	public key: untrusted comment line, then base64("Ed" || key id (8) || public key (32))
//	signature:  untrusted comment line, then base64(algorithm (2) || key id (8) || signature (64)),
//	            "trusted comment: " line, then base64(global signature (64))

import (
	"bytes"
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// minisignKey is a minisign public key.
type minisignKey struct {
	name string // the embedded file it came from, for messages
	id   [8]byte
	pub  ed25519.PublicKey
}

// minisignSignature is a parsed minisign signature file.
type minisignSignature struct {
	algorithm      string // "Ed" (legacy) or "ED" (prehashed)
	keyID          [8]byte
	signature      []byte
	trustedComment string
	globalSig      []byte
}

// keyIDString renders a key id the way minisign prints it.
func keyIDString(id [8]byte) string {
	// minisign stores the id little-endian and prints it as a number.
	var b [8]byte
	for i := range id {
		b[i] = id[7-i]
	}
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// minisignDataLines returns the lines of a minisign file without line
// endings, with trailing empty lines removed.
func minisignDataLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	return lines
}

func parseMinisignPublicKey(name string, data []byte) (minisignKey, error) {
	lines := minisignDataLines(data)
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "untrusted comment:") {
		return minisignKey{}, fmt.Errorf("%s: not a minisign public key file", name)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return minisignKey{}, fmt.Errorf("%s: public key is not valid base64: %w", name, err)
	}
	if len(raw) != 2+8+ed25519.PublicKeySize || string(raw[:2]) != "Ed" {
		return minisignKey{}, fmt.Errorf("%s: not an Ed25519 minisign public key", name)
	}
	k := minisignKey{name: name, pub: ed25519.PublicKey(bytes.Clone(raw[10:]))}
	copy(k.id[:], raw[2:10])
	return k, nil
}

func parseMinisignSignature(data []byte) (minisignSignature, error) {
	lines := minisignDataLines(data)
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "untrusted comment:") {
		return minisignSignature{}, errors.New("not a minisign signature file")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return minisignSignature{}, fmt.Errorf("signature is not valid base64: %w", err)
	}
	if len(raw) != 2+8+ed25519.SignatureSize {
		return minisignSignature{}, errors.New("signature has the wrong length")
	}
	s := minisignSignature{algorithm: string(raw[:2]), signature: raw[10:]}
	copy(s.keyID[:], raw[2:10])
	if s.algorithm != "Ed" && s.algorithm != "ED" {
		return minisignSignature{}, fmt.Errorf("unsupported signature algorithm %q", s.algorithm)
	}
	const prefix = "trusted comment: "
	if !strings.HasPrefix(lines[2], prefix) {
		return minisignSignature{}, errors.New("trusted comment line missing")
	}
	s.trustedComment = strings.TrimPrefix(lines[2], prefix)
	if s.globalSig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3])); err != nil {
		return minisignSignature{}, fmt.Errorf("trusted comment signature is not valid base64: %w", err)
	}
	if len(s.globalSig) != ed25519.SignatureSize {
		return minisignSignature{}, errors.New("trusted comment signature has the wrong length")
	}
	return s, nil
}

// minisignVerify checks that sigFile is a valid signature of msg by one of
// keys, including the signature of its trusted comment. It returns the key
// that made the signature.
func minisignVerify(keys []minisignKey, msg, sigFile []byte) (minisignKey, error) {
	s, err := parseMinisignSignature(sigFile)
	if err != nil {
		return minisignKey{}, err
	}
	for _, k := range keys {
		if k.id != s.keyID {
			continue
		}
		signed := msg
		if s.algorithm == "ED" {
			h := blake2b.Sum512(msg)
			signed = h[:]
		}
		if !ed25519.Verify(k.pub, signed, s.signature) {
			return minisignKey{}, fmt.Errorf("signature by key %s (%s) does not verify", keyIDString(k.id), k.name)
		}
		global := append(bytes.Clone(s.signature), s.trustedComment...)
		if !ed25519.Verify(k.pub, global, s.globalSig) {
			return minisignKey{}, fmt.Errorf("trusted comment signature by key %s (%s) does not verify", keyIDString(k.id), k.name)
		}
		return k, nil
	}
	return minisignKey{}, fmt.Errorf("signed with key %s, which is not one of the embedded release keys", keyIDString(s.keyID))
}

// releaseKeysFS holds the release signing public keys. tools/release-sign.sh
// keygen writes them. A build without them cannot verify any update.
//
//go:embed keys
var releaseKeysFS embed.FS

// releaseKeyFiles are the accepted keys: a signature by either is valid.
// The reserve key takes over if the main key is lost or compromised.
var releaseKeyFiles = []string{"keys/main.pub", "keys/reserve.pub"}

// releaseKeys returns the embedded release signing keys.
func releaseKeys() ([]minisignKey, error) {
	var keys []minisignKey
	for _, name := range releaseKeyFiles {
		data, err := releaseKeysFS.ReadFile(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		k, err := parseMinisignPublicKey(name, data)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("this build embeds no release signing keys, so no update can be verified")
	}
	return keys, nil
}
