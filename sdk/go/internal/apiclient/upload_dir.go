package apiclient

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
)

// FeatureExtract is the toolboxd feature behind upload's extract=true
// (plans/agent-sandbox-feature-parity.md, F3). An older agent ignores it
// and would store the archive itself as a file named like the folder.
const FeatureExtract = "files.extract"

// UploadDir copies the folder localDir into remoteDir in the sandbox (made
// if missing): it packs the folder as a gzipped tar while sending it, and
// toolboxd unpacks it safely (no entry can land outside remoteDir). Symlinks
// are sent as links; hard-linked files as separate files; devices, pipes
// and sockets are skipped. The tar is built as it is sent, so it is sent
// once and never retried.
func (c *Client) UploadDir(ctx context.Context, id, localDir, remoteDir string) error {
	info, err := os.Stat(localDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a folder", localDir)
	}
	if err := c.RequireToolboxFeatures(ctx, id, FeatureExtract); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(WriteDirTar(pw, localDir))
	}()
	defer pr.Close()
	target := c.baseURL + c.toolboxPath(id, "/files/upload", url.Values{"extract": {"true"}})
	return c.sendUploadStream(ctx, target, remoteDir, "upload.tar.gz", pr)
}

// WriteDirTar writes the contents of localDir to w as a gzipped tar, names
// relative to localDir. It is what UploadDir sends; the aerolvm CLI uses it
// too.
func WriteDirTar(w io.Writer, localDir string) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	root := filepath.Clean(localDir)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		link := ""
		switch mode := info.Mode(); {
		case mode&fs.ModeSymlink != 0:
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		case mode.IsDir(), mode.IsRegular():
		default:
			// Devices, pipes and sockets have no meaning in another
			// machine's folder, and the sandbox refuses them anyway.
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		// Owners mean nothing in the sandbox; leave them to the agent.
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	return errors.Join(tw.Close(), gz.Close())
}
