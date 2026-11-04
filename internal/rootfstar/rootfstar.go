// Package rootfstar turns a VM's root filesystem into the tar stream of a
// one-layer container image, and checks such a stream on its way into the
// image store.
//
// A Firecracker snapshot is built in two halves. Inside a helper VM, the
// guest kernel mounts a copy of the sandbox's disk and the agent walks it
// with Write: the host kernel never parses a filesystem the tenant could
// have crafted. On the host, Filter reads the helper's stream as untrusted
// input (a guest that broke out of its kernel's ext4 code could send
// anything) before the image store sees it.
package rootfstar

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Write writes the tree under root as a tar stream that keeps what a
// container image layer needs: numeric owners, modes, symlinks, hard links,
// device and fifo nodes, and extended attributes (file capabilities such as
// ping's live in security.capability). Sockets are left out: one is only a
// name for a listener that died with the VM, tar cannot hold it, and docker
// export leaves them out too. Symlinks are stored, never followed.
func Write(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	seen := map[[2]uint64]string{} // (dev, inode) of files with several links -> first name
	xattrBuf := make([]byte, xattrMax)
	// Not os.DirFS: it refuses names that are not UTF-8, and a guest may
	// have any bytes in its file names.
	root = filepath.Clean(root)
	prefix := root + string(filepath.Separator)
	err := filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, prefix))
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSocket != 0 {
			return nil
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("/%s: %w", rel, err)
		}
		hdr.Name = rel
		if info.IsDir() {
			hdr.Name += "/"
		}
		// Numeric owners: the host's user names mean nothing in the image.
		hdr.Uname, hdr.Gname = "", ""
		if st, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode().IsRegular() && st.Nlink > 1 {
			key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
			if first, ok := seen[key]; ok {
				hdr.Typeflag, hdr.Linkname, hdr.Size = tar.TypeLink, first, 0
			} else {
				seen[key] = hdr.Name
			}
		}
		if xattrs := readXattrs(p, xattrBuf); len(xattrs) > 0 {
			hdr.PAXRecords = map[string]string{}
			for name, value := range xattrs {
				hdr.PAXRecords["SCHILY.xattr."+name] = value
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("/%s: %w", rel, err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		f.Close()
		if err != nil {
			return fmt.Errorf("/%s: %w", rel, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// xattrMax is Linux's cap on both an attribute name list and one value
// (XATTR_LIST_MAX, XATTR_SIZE_MAX), so one buffer this size always fits.
const xattrMax = 64 << 10

// readXattrs returns path's extended attributes, or none where the
// filesystem or platform has none to give. buf is scratch space of xattrMax
// bytes, reused across calls. A missing attribute only loses what the image
// could carry, so errors are not fatal.
func readXattrs(p string, buf []byte) map[string]string {
	size, err := unix.Llistxattr(p, buf)
	if err != nil || size <= 0 {
		return nil
	}
	names := strings.Split(strings.TrimRight(string(buf[:size]), "\x00"), "\x00")
	out := map[string]string{}
	for _, name := range names {
		n, err := unix.Lgetxattr(p, name, buf)
		if err != nil {
			continue
		}
		out[name] = string(buf[:n])
	}
	return out
}

// ErrTooLarge: the stream carried more than Filter's byte limit.
var ErrTooLarge = errors.New("rootfs stream exceeds its size limit")

// Filter copies the tar stream src to dst, dropping every entry excluded
// names (an excluded directory takes everything under it, and a hard link
// to an excluded file goes with it), and refusing a stream that is not a
// well-formed, complete tar of relative paths: an entry name or link target
// that is absolute or climbs out with "..", a stream cut short (no
// end-of-archive), or more than maxBytes of it in all. Names are matched as
// guest paths: "/" + the cleaned entry name.
//
// The output is re-encoded entry by entry, so nothing in it is a byte the
// source chose outside a header field or file body Filter checked.
func Filter(dst io.Writer, src io.Reader, excluded func(guestPath string) bool, maxBytes int64) error {
	counted := &countingReader{r: src, limit: maxBytes}
	tr := tar.NewReader(counted)
	tw := tar.NewWriter(dst)
	var droppedDirs []string
	under := func(guestPath string) bool {
		if excluded != nil && excluded(guestPath) {
			return true
		}
		for _, dir := range droppedDirs {
			if strings.HasPrefix(guestPath, dir+"/") {
				return true
			}
		}
		return false
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return wrapStreamErr(counted, err)
		}
		guestPath, err := safePath(hdr.Name)
		if err != nil {
			return err
		}
		if under(guestPath) {
			if hdr.Typeflag == tar.TypeDir {
				droppedDirs = append(droppedDirs, guestPath)
			}
			continue
		}
		// A symlink's target is kept as written: the engine resolves it
		// inside the container, never on the host. A hard link's names a
		// file in this stream.
		if hdr.Typeflag == tar.TypeLink {
			target, err := safePath(hdr.Linkname)
			if err != nil {
				return err
			}
			if under(target) {
				continue
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("%s: %w", guestPath, err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			return wrapStreamErr(counted, fmt.Errorf("%s: %w", guestPath, err))
		}
	}
	return tw.Close()
}

// safePath returns the guest path an entry name or hard-link target stands
// for, or an error if it is absolute or leaves the root.
func safePath(name string) (string, error) {
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("rootfs stream: unsafe entry name %q", name)
	}
	for _, part := range strings.Split(trimmed, "/") {
		if part == ".." {
			return "", fmt.Errorf("rootfs stream: unsafe entry name %q", name)
		}
	}
	return path.Clean("/" + trimmed), nil
}

func wrapStreamErr(c *countingReader, err error) error {
	if c.over {
		return ErrTooLarge
	}
	return fmt.Errorf("rootfs stream: %w", err)
}

// countingReader fails once more than limit bytes have been read.
type countingReader struct {
	r     io.Reader
	n     int64
	limit int64
	over  bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.over {
		return 0, ErrTooLarge
	}
	// One byte past the limit is read, so a stream that ends exactly at it
	// is told from one that goes on.
	if remaining := c.limit - c.n + 1; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.limit {
		c.over = true
		return 0, ErrTooLarge
	}
	return n, err
}
