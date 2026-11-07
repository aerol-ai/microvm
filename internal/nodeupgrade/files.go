package nodeupgrade

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MaxFileBytes caps one file of an upgrade. A release binary is under
// 100 MiB [measured: v0.6.11 sandboxd 77 MiB]; the cap stops a bad source
// from filling the disk (plans/kubectl-style-cluster-ops.md §8).
const MaxFileBytes = 1 << 30

// maxFileBytes is MaxFileBytes; tests lower it.
var maxFileBytes int64 = MaxFileBytes

// midSwapHook runs inside swapIn after the old file is kept as *.prev and
// before the new one is renamed into place: the crash-safety tests stop
// the upgrader there. Nil in production.
var midSwapHook func(dst string)

// fileSHA256 hashes a file as it streams; "" with a nil error when there is
// no file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// writeFileAtomic replaces path with data in one rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// copyFile copies src to dst (created or truncated) with mode and syncs
// it.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(mode); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// streamToFile writes r to dst while hashing it, never holding more than a
// buffer in memory (eng review Section 4), and refuses more than
// MaxFileBytes. It returns the size and the hex SHA-256.
func streamToFile(r io.Reader, dst string, mode os.FileMode) (int64, string, error) {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, maxFileBytes+1))
	if err == nil && n > maxFileBytes {
		err = fmt.Errorf("larger than %d bytes", maxFileBytes)
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// containsMarker reports whether the file holds marker anywhere, reading it
// in chunks. It is how the upgrader asks whether a binary has a command
// before running it: a sandboxd older than `sandboxd version` takes an
// unknown first argument as none and boots a second daemon on the live
// state directory.
func containsMarker(path string, marker []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	buf := make([]byte, 1<<20)
	carry := []byte{}
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := append(carry, buf[:n]...)
			if bytes.Contains(chunk, marker) {
				return true
			}
			keep := len(marker) - 1
			if keep > len(chunk) {
				keep = len(chunk)
			}
			carry = append([]byte{}, chunk[len(chunk)-keep:]...)
		}
		if err != nil {
			return false
		}
	}
}

// swapIn installs staged at dst, keeping the file it replaces as dst.prev.
// At every moment dst exists: the old file is linked to dst.prev first, and
// the new one is renamed over dst in one step.
func swapIn(staged, dst string) error {
	tmp := dst + ".new"
	if err := copyFile(staged, tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("copy %s: %w", dst, err)
	}
	if _, err := os.Lstat(dst); err == nil {
		prev := dst + ".prev"
		if err := os.Remove(prev); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(tmp)
			return fmt.Errorf("remove old %s: %w", prev, err)
		}
		if err := os.Link(dst, prev); err != nil {
			// A file system without hard links: a copy keeps the same
			// guarantee, with the old file's size again on disk.
			if cerr := copyFile(dst, prev, 0o755); cerr != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("keep %s: %w", prev, cerr)
			}
		}
	} else if !os.IsNotExist(err) {
		_ = os.Remove(tmp)
		return err
	}
	if midSwapHook != nil {
		midSwapHook(dst)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", dst, err)
	}
	syncDir(filepath.Dir(dst))
	return nil
}

// errPrevMismatch means dst.prev is not the file the op replaced.
var errPrevMismatch = errors.New("is not the file the upgrade replaced")

// putBack reinstalls dst.prev at dst, but only when it is the file the
// operation replaced (prevSHA256). With no file before (prevSHA256 empty)
// it removes dst.
func putBack(dst, prevSHA256 string) error {
	if prevSHA256 == "" {
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	prev := dst + ".prev"
	got, err := fileSHA256(prev)
	if err != nil {
		return err
	}
	if got != prevSHA256 {
		return fmt.Errorf("%s %w (sha256 %s, want %s)", prev, errPrevMismatch, orNone(got), prevSHA256)
	}
	tmp := dst + ".new"
	if err := copyFile(prev, tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(dst))
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
