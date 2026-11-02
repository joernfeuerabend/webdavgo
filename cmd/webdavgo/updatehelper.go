// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// updatehelper.go is "webdavgo apply-update", the root helper that
// webdavgo-update.service runs when the admin UI has placed an update
// request (see update.go).
//
// The helper runs as root and must not trust the webdavgo service, which
// owns the update directory. It therefore
//   - opens the directory through os.Root, so that symlinks cannot lead it
//     elsewhere, and reads only regular files of bounded size,
//   - checks the minisign signature of SHA256SUMS against the release keys
//     embedded in itself, the installed root-owned binary,
//   - checks the SHA-256 of the tarball against the signed SHA256SUMS,
//   - takes the new version from the tarball name in the signed SHA256SUMS
//     and refuses anything not newer than itself,
//
// and only then keeps the current binary in previousBinDir, installs the
// new one, restarts the service and writes updateStatusFile.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"syscall"
	"time"
)

func runApplyUpdate(args []string) int {
	if len(args) > 0 {
		logger.Error("usage: webdavgo apply-update (run by webdavgo-update.service)")
		return 2
	}
	if containerMode {
		logger.Error("apply-update does not run in a container, updates come as a new image tag")
		return 1
	}
	if os.Geteuid() != 0 {
		logger.Error("apply-update must run as root, it is started by webdavgo-update.service")
		return 1
	}
	base, err := os.OpenRoot(installData)
	if err != nil {
		logger.Error("cannot open the data directory", "path", installData, "err", err)
		return 1
	}
	defer base.Close()
	dir, err := base.OpenRoot(path.Base(updateDir))
	if err != nil {
		logger.Error("cannot open the update directory", "path", updateDir, "err", err)
		return 1
	}
	defer dir.Close()

	// The request is consumed first: whatever happens next, the path unit
	// does not start the helper again for it.
	if err := dir.Remove(updateRequestFile); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			logger.Info("no update request", "path", updateDir+"/"+updateRequestFile)
			return 0
		}
		logger.Error("cannot remove the update request", "err", err)
		return 1
	}

	st := applyUpdate(dir)
	st.Time = time.Now().UTC()
	removeUpdateFiles(dir)
	if err := writeUpdateStatus(dir, st); err != nil {
		logger.Error("cannot write the update status", "err", err)
	}
	if !st.OK {
		logger.Error("update failed", "from", st.From, "to", st.To, "reason", st.Message)
		return 1
	}
	logger.Info("update installed", "from", st.From, "to", st.To)
	return 0
}

// applyUpdate verifies and installs the requested update.
func applyUpdate(dir *os.Root) updateStatus {
	st := updateStatus{From: version}
	fail := func(format string, a ...any) updateStatus {
		st.Message = fmt.Sprintf(format, a...)
		return st
	}
	installed, err := installedVersion()
	if err != nil {
		return fail("%v", err)
	}
	sums, err := readUpdateFile(dir, updateSumsFile, maxUpdateSums)
	if err != nil {
		return fail("%v", err)
	}
	sig, err := readUpdateFile(dir, updateSigFile, maxUpdateSig)
	if err != nil {
		return fail("%v", err)
	}
	entry, err := verifySignedSums(sums, sig)
	if err != nil {
		return fail("verification failed: %v", err)
	}
	st.To = "v" + entry.version.String()
	if !entry.version.newerThan(installed) {
		return fail("refused: %s is not newer than the installed version %s", st.To, version)
	}
	tarball, err := readUpdateFile(dir, entry.name, maxUpdateTarball)
	if err != nil {
		return fail("%v", err)
	}
	if sha256.Sum256(tarball) != entry.sum {
		return fail("verification failed: the SHA-256 of %s does not match the signed SHA256SUMS", entry.name)
	}
	bin, err := binaryFromTarball(tarball)
	if err != nil {
		return fail("%s: %v", entry.name, err)
	}

	if err := os.MkdirAll(previousBinDir, 0755); err != nil {
		return fail("cannot create %s: %v", previousBinDir, err)
	}
	if err := os.Chmod(previousBinDir, 0755); err != nil {
		return fail("cannot chmod %s: %v", previousBinDir, err)
	}
	if err := copyAtomic(installBin, previousBin, 0755); err != nil {
		return fail("cannot keep the current binary: %v", err)
	}
	if err := writeAtomic(installBin, bin, 0755); err != nil {
		return fail("cannot install the new binary: %v", err)
	}
	logger.Info("new binary installed, restarting the service", "from", st.From, "to", st.To, "previous", previousBin)
	if err := systemctl("restart", serviceName+".service"); err != nil {
		return fail("%s is installed, but the service did not restart: %v (journalctl -u %s shows why, the previous binary is kept as %s)",
			st.To, err, serviceName, previousBin)
	}
	st.OK = true
	st.Message = fmt.Sprintf("Updated from %s to %s. The previous binary is kept as %s.", st.From, st.To, previousBin)
	return st
}

// readUpdateFile reads a regular file of at most limit bytes from the
// update directory. O_NONBLOCK keeps a FIFO from blocking the open.
func readUpdateFile(dir *os.Root, name string, limit int64) ([]byte, error) {
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return data, nil
}

// binaryFromTarball returns the webdavgo binary from a release tarball.
func binaryFromTarball(tarball []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("contains no webdavgo binary")
		}
		if err != nil {
			return nil, err
		}
		if path.Clean(h.Name) != "webdavgo" {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, errors.New("webdavgo in the tarball is not a regular file")
		}
		if h.Size <= 0 || h.Size > maxUpdateBinary {
			return nil, fmt.Errorf("webdavgo in the tarball has an implausible size (%d bytes)", h.Size)
		}
		bin, err := io.ReadAll(io.LimitReader(tr, maxUpdateBinary+1))
		if err != nil {
			return nil, err
		}
		if int64(len(bin)) != h.Size {
			return nil, errors.New("webdavgo in the tarball is truncated")
		}
		return bin, nil
	}
}

// removeUpdateFiles deletes the downloaded files once they are handled.
// Root.Remove does not follow symlinks.
func removeUpdateFiles(dir *os.Root) {
	entries, err := fs.ReadDir(dir.FS(), ".")
	if err != nil {
		logger.Warn("cannot list the update directory", "err", err)
		return
	}
	for _, e := range entries {
		if e.Name() == updateStatusFile || e.IsDir() {
			continue
		}
		if err := dir.Remove(e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("cannot remove a file in the update directory", "name", e.Name(), "err", err)
		}
	}
}

// writeUpdateStatus replaces updateStatusFile through a new temporary file
// and a rename, so that nothing the service placed there is written to.
func writeUpdateStatus(dir *os.Root, st updateStatus) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	var rnd [8]byte
	rand.Read(rnd[:])
	tmp := ".status-" + hex.EncodeToString(rnd[:])
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer dir.Remove(tmp) // no-op after the rename
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return dir.Rename(tmp, updateStatusFile)
}
