// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// admincert.go – TLS for the admin listener.
//
// The admin UI is never served in plain text, not even on localhost, so it
// needs a certificate before any domain is configured. A self-signed one is
// created once and kept in cert_dir; the operator verifies it by comparing
// the browser's fingerprint with the one in the log and the setup banner.
// With tls_mode = "acme", a handshake for the configured domain gets the
// ACME certificate instead, so access by domain shows no warning while
// access by IP or localhost keeps working.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	adminCertFile = "admin-selfsigned.crt"
	adminKeyFile  = "admin-selfsigned.key"
	// No CA will ever vouch for this certificate, so a short validity only
	// adds browser warnings for the operator without adding security.
	adminCertValidity = 10 * 365 * 24 * time.Hour
)

// loadOrCreateAdminCert returns the self-signed admin certificate from dir,
// creating it first if either file is missing. Regenerating only when
// missing keeps the fingerprint stable, so a browser exception the operator
// accepted once stays valid across restarts.
func loadOrCreateAdminCert(dir string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, adminCertFile)
	keyPath := filepath.Join(dir, adminKeyFile)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return tls.Certificate{}, fmt.Errorf("load admin certificate from %s: %w", dir, err)
	}
	if err := createAdminCert(certPath, keyPath); err != nil {
		return tls.Certificate{}, err
	}
	cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load new admin certificate: %w", err)
	}
	logger.Info("admin certificate created", "path", certPath)
	return cert, nil
}

func createAdminCert(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return fmt.Errorf("create cert_dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate admin key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	dnsNames := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" && h != "localhost" {
		dnsNames = append(dnsNames, h)
	}
	ips := append([]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, lanAddrs()...)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "webdavgo admin"},
		NotBefore:    now.Add(-time.Hour), // tolerate small clock skew
		NotAfter:     now.Add(adminCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Not a CA: Firefox refuses to let the user override the warning for
		// a CA certificate that is used as a server certificate.
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create admin certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal admin key: %w", err)
	}
	// Key first: a certificate without its key would be loaded as "present"
	// and fail on every start instead of being regenerated.
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0600); err != nil {
		return err
	}
	return writePEM(certPath, "CERTIFICATE", der, 0644)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// certFingerprint formats the SHA-256 fingerprint of the leaf the way
// browsers display it, so the operator can compare it character by
// character.
func certFingerprint(c tls.Certificate) string {
	if len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// adminTLSConfig serves the self-signed certificate, or the ACME
// certificate when the client asks for the configured domain. Both are
// looked up per handshake, so a domain set up later in the wizard applies
// without a restart.
func adminTLSConfig(selfSigned tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if acme := currentCerts(); acme != nil && strings.EqualFold(hello.ServerName, currentConfig().Domain) {
				// Until the first certificate is obtained there is none for the
				// domain; the self-signed one still lets the admin in.
				if c, err := acme.TLSConfig().GetCertificate(hello); err == nil && c != nil {
					return c, nil
				}
			}
			return &selfSigned, nil
		},
	}
}

// certFileFingerprint returns the fingerprint of the PEM certificate at
// path, for commands that must not touch the private key.
func certFileFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s: no PEM certificate", path)
	}
	return certFingerprint(tls.Certificate{Certificate: [][]byte{block.Bytes}}), nil
}

// lanAddrs returns the addresses of all interfaces that are up, IPv4 first.
// Loopback is left out because it is listed separately, and link-local
// addresses because a URL with an IPv6 zone is unusable on other devices and
// IPv4 link-local means DHCP failed.
func lanAddrs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Warn("cannot list network interfaces", "err", err)
		return nil
	}
	var v4, v6 []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil {
				v4 = append(v4, ip4)
			} else {
				v6 = append(v6, ipn.IP)
			}
		}
	}
	return append(v4, v6...)
}
