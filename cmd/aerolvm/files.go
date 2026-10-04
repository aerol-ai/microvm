package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/internal/agenttools"
)

// remotePath splits "<sandbox>:<path>". A one-letter prefix is a Windows
// drive ("C:\data"), and a prefix with a path separator is a local path that
// happens to contain a colon, so both stay local.
func remotePath(arg string) (ref, p string, ok bool) {
	ref, p, found := strings.Cut(arg, ":")
	if !found || ref == "" || len(ref) == 1 || strings.ContainsAny(ref, `/\`) {
		return "", "", false
	}
	return ref, p, true
}

func runCp(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("cp")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "cp", err)
	}
	if len(pos) != 2 {
		return a.usageError(c, "cp", "expected <src> <dst>")
	}
	srcRef, srcPath, srcRemote := remotePath(pos[0])
	dstRef, dstPath, dstRemote := remotePath(pos[1])
	switch {
	case srcRemote == dstRemote && srcRemote:
		return a.usageError(c, "cp", "copy between two sandboxes is not supported; copy through this machine")
	case srcRemote == dstRemote:
		return a.usageError(c, "cp", "one side must be <sandbox>:<path>")
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if srcRemote {
		return a.download(ctx, c, tools, srcRef, srcPath, pos[1])
	}
	return a.upload(ctx, c, tools, pos[0], dstRef, dstPath)
}

func (a *app) download(ctx context.Context, c *commonFlags, tools *agenttools.Tools, ref, remote, local string) int {
	if strings.TrimSpace(remote) == "" {
		return a.usageError(c, "cp", "the sandbox path is empty")
	}
	sb, err := tools.Target(ctx, ref)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	body, err := sb.DownloadFileStream(ctx, remote)
	if err != nil {
		return a.fail(c, agenttools.Classify(err), exitError)
	}
	defer body.Close()
	if local == "-" {
		if _, err := io.Copy(a.stdout, body); err != nil {
			return a.fail(c, err, exitError)
		}
		return exitOK
	}
	if info, err := os.Stat(local); err == nil && info.IsDir() {
		local = filepath.Join(local, path.Base(remote))
	}
	// Write to a temp file and rename, so a failed copy never leaves a
	// truncated file where the old one was.
	dir := filepath.Dir(local)
	tmp, err := os.CreateTemp(dir, ".aerolvm-cp-*")
	if err != nil {
		return a.fail(c, err, exitError)
	}
	n, copyErr := io.Copy(tmp, body)
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(tmp.Name())
		return a.fail(c, errors.Join(copyErr, closeErr), exitError)
	}
	if err := os.Rename(tmp.Name(), local); err != nil {
		_ = os.Remove(tmp.Name())
		return a.fail(c, err, exitError)
	}
	return a.reportCopy(c, ref+":"+remote, local, n)
}

func (a *app) upload(ctx context.Context, c *commonFlags, tools *agenttools.Tools, local, ref, remote string) int {
	var src io.Reader = a.stdin
	name := "stdin"
	if local != "-" {
		info, err := os.Stat(local)
		if err != nil {
			return a.fail(c, err, exitError)
		}
		if info.IsDir() {
			return a.fail(c, &agenttools.Error{
				Code:    agenttools.CodeInvalidArgument,
				Message: local + " is a directory; cp copies files",
				Hint:    "copy a directory with tar: tar -C " + local + " -cf - . | aerolvm exec " + ref + " -- tar -C /dest -xf -",
			}, exitError)
		}
		f, err := os.Open(local)
		if err != nil {
			return a.fail(c, err, exitError)
		}
		defer f.Close()
		src = f
		name = filepath.Base(local)
	}
	if remote == "" || strings.HasSuffix(remote, "/") {
		if local == "-" {
			return a.usageError(c, "cp", "name the destination file when copying from stdin")
		}
		remote += name
	}
	sb, err := tools.Target(ctx, ref)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	counter := &countingReader{r: src}
	if err := sb.UploadFileStream(ctx, remote, counter); err != nil {
		return a.fail(c, agenttools.Classify(err), exitError)
	}
	return a.reportCopy(c, local, ref+":"+remote, counter.n)
}

func (a *app) reportCopy(c *commonFlags, src, dst string, n int64) int {
	if c.json {
		a.printJSON(map[string]any{"source": src, "destination": dst, "bytes": n})
		return exitOK
	}
	a.note("copied %d bytes: %s -> %s", n, src, dst)
	return exitOK
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func runLs(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("ls")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "ls", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "ls", "expected <sandbox>:<path>")
	}
	ref, dir, ok := remotePath(pos[0])
	if !ok {
		ref, dir = pos[0], ""
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	sb, err := tools.Target(ctx, ref)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	list, err := tools.ListFiles(ctx, sb, dir)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(list)
		return exitOK
	}
	for _, e := range list.Entries {
		if e.IsDir {
			fmt.Fprintln(a.stdout, e.Name+"/")
		} else {
			fmt.Fprintln(a.stdout, e.Name)
		}
	}
	if list.Truncated {
		a.note("aerolvm: listing cut at %d entries", len(list.Entries))
	}
	return exitOK
}
