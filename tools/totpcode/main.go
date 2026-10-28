// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

// Command totpcode prints the RFC 6238 code (SHA-1, 6 digits, 30 s) for a
// Base32 secret. test.sh uses it to log in as an admin; it is a separate
// program so that the server binary contains no code generator, and an
// independent implementation also checks the server's one.
//
// Usage: totpcode <base32-secret> [unix-time]
package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: totpcode <base32-secret> [unix-time]")
		os.Exit(2)
	}
	secret := strings.ToUpper(strings.ReplaceAll(os.Args[1], " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid secret:", err)
		os.Exit(2)
	}
	t := time.Now().Unix()
	if len(os.Args) == 3 {
		if t, err = strconv.ParseInt(os.Args[2], 10, 64); err != nil {
			fmt.Fprintln(os.Stderr, "invalid time:", err)
			os.Exit(2)
		}
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t/30))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	fmt.Printf("%06d\n", v%1000000)
}
