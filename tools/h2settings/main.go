// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

// Command h2settings prints the SETTINGS_MAX_CONCURRENT_STREAMS value an
// HTTP/2 server announces (RFC 9113 section 6.5.2). test.sh uses it because
// curl does not show the server's SETTINGS frame. Only the standard library
// is used: the probe sends the connection preface and an empty SETTINGS
// frame, then reads frames until the server's first SETTINGS frame.
//
// Usage: h2settings <host:port> <ca-file>
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	frameSettings        = 0x4
	settingMaxConcurrent = 0x3
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: h2settings <host:port> <ca-file>")
		os.Exit(2)
	}
	pem, err := os.ReadFile(os.Args[2])
	if err != nil {
		fail(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	conn, err := tls.Dial("tcp", os.Args[1], &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h2"}})
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		fail(fmt.Errorf("server did not negotiate h2 (got %q)", p))
	}
	// Preface plus an empty SETTINGS frame (RFC 9113 section 3.4).
	if _, err := conn.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, frameSettings, 0, 0, 0, 0, 0)); err != nil {
		fail(err)
	}
	for {
		var hdr [9]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			fail(err)
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			fail(err)
		}
		if hdr[3] != frameSettings {
			continue
		}
		for i := 0; i+6 <= len(payload); i += 6 {
			if binary.BigEndian.Uint16(payload[i:]) == settingMaxConcurrent {
				fmt.Println(binary.BigEndian.Uint32(payload[i+2:]))
				return
			}
		}
		fmt.Println("unlimited")
		return
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "h2settings:", err)
	os.Exit(1)
}
