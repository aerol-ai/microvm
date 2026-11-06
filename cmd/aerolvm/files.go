package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/safetar"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
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
	var recursive bool
	fs.BoolVar(&recursive, "r", false, "")
	fs.BoolVar(&recursive, "recursive", false, "")
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
	case recursive && (pos[0] == "-" || pos[1] == "-"):
		return a.usageError(c, "cp", "cp -r copies a folder; it cannot read stdin or write stdout")
	}
	tools, err := a.tools(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	switch {
	case recursive && srcRemote:
		return a.downloadDir(ctx, c, tools, srcRef, srcPath, pos[1])
	case recursive:
		return a.uploadDir(ctx, c, tools, pos[0], dstRef, dstPath)
	case srcRemote:
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
				Hint:    "copy a directory with -r: aerolvm cp -r " + local + " " + ref + ":/dest",
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
	tools, err := a.tools(ctx, c)
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

// cp -r moves a folder as a tar (plans/agent-sandbox-feature-parity.md, F3
// and X4). Up, the SDK sends it with extract=true and toolboxd unpacks it.
// Down, tar runs in the sandbox over a streamed exec and the archive is
// unpacked here through internal/safetar: it comes from a sandbox, which is
// untrusted, and lands on this machine, so every entry is checked and every
// write stays inside the target folder (CEO review R9).

// cpDirLimits caps a folder download: enough for a large source tree, not
// enough for a hostile archive to fill this machine's disk unnoticed.
var cpDirLimits = safetar.Limits{MaxEntries: 1_000_000, MaxBytes: 16 << 30}

// noTarExit is the exit code of the download command when the image has no
// tar, the shell's "command not found".
const noTarExit = 127

// requireTarSandbox refuses the runtimes that cannot run tar or unpack an
// archive, naming why.
func requireTarSandbox(sb *microvm.Sandbox) error {
	switch {
	case agenttools.IsWasm(sb):
		return &agenttools.Error{
			Code:    agenttools.CodeUnsupportedRuntime,
			Message: "cp -r needs a container or VM sandbox: a WASM sandbox has no tar and cannot unpack a folder archive",
			Hint:    "copy the files one at a time with aerolvm cp",
		}
	case strings.TrimSpace(sb.Runtime) == models.RuntimeIsolate:
		return &agenttools.Error{
			Code:    agenttools.CodeUnsupportedRuntime,
			Message: "cp -r needs a container or VM sandbox: a V8 isolate sandbox has no files",
		}
	}
	return nil
}

func (a *app) uploadDir(ctx context.Context, c *commonFlags, tools *agenttools.Tools, local, ref, remote string) int {
	info, err := os.Stat(local)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if !info.IsDir() {
		return a.fail(c, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: local + " is a file; cp -r copies folders",
			Hint:    "drop -r to copy a file",
		}, exitError)
	}
	if strings.TrimSpace(remote) == "" {
		return a.usageError(c, "cp", "name the destination folder in the sandbox")
	}
	if strings.HasSuffix(remote, "/") {
		remote += filepath.Base(filepath.Clean(local))
	}
	sb, err := tools.Target(ctx, ref)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if err := requireTarSandbox(sb); err != nil {
		return a.fail(c, err, exitError)
	}
	if err := sb.UploadDir(ctx, local, remote); err != nil {
		return a.fail(c, agenttools.Classify(err), exitError)
	}
	return a.reportDirCopy(c, local, ref+":"+remote, nil)
}

func (a *app) downloadDir(ctx context.Context, c *commonFlags, tools *agenttools.Tools, ref, remote, local string) int {
	if strings.TrimSpace(remote) == "" {
		return a.usageError(c, "cp", "the sandbox path is empty")
	}
	dest := local
	if info, err := os.Stat(local); err == nil && info.IsDir() {
		dest = filepath.Join(local, path.Base(path.Clean(remote)))
	}
	sb, err := tools.Target(ctx, ref)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if err := requireTarSandbox(sb); err != nil {
		return a.fail(c, err, exitError)
	}
	if err := os.Mkdir(dest, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return a.fail(c, err, exitError)
	}
	res, err := streamDirInto(ctx, sb, remote, dest)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	return a.reportDirCopy(c, ref+":"+remote, dest, &res)
}

// streamDirInto runs tar in the sandbox and unpacks its output into dest as
// it arrives.
func streamDirInto(ctx context.Context, sb *microvm.Sandbox, remote, dest string) (safetar.Result, error) {
	pr, pw := io.Pipe()
	var stderrMu sync.Mutex
	var stderr bytes.Buffer
	handle, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command: "command -v tar >/dev/null 2>&1 || { echo 'aerolvm: no tar in this sandbox image' >&2; exit 127; }; exec tar -C " + shellQuote(remote) + " -cf - .",
		// The pipe hands each chunk to the unpacker, so a slow disk here
		// slows the sandbox's tar instead of growing memory. Once the
		// unpacker stops (done, or refused an entry) the write fails and the
		// rest is dropped.
		OnStdout: func(b []byte) { _, _ = pw.Write(b) },
		OnStderr: func(b []byte) {
			stderrMu.Lock()
			defer stderrMu.Unlock()
			if stderr.Len() < 4096 {
				stderr.Write(b)
			}
		},
	})
	if err != nil {
		return safetar.Result{}, agenttools.Classify(err)
	}
	type extracted struct {
		res safetar.Result
		err error
	}
	done := make(chan extracted, 1)
	go func() {
		res, err := safetar.Extract(pr, dest, cpDirLimits)
		if err != nil {
			// Stop the sandbox's tar: nothing more will be read.
			_ = pr.CloseWithError(err)
			_ = handle.Signal("KILL")
		} else {
			// Drain the end-of-archive padding tar still writes.
			_, _ = io.Copy(io.Discard, pr)
		}
		done <- extracted{res, err}
	}()
	exit, waitErr := handle.Wait()
	_ = pw.Close()
	out := <-done
	stderrMu.Lock()
	message := strings.TrimSpace(stderr.String())
	stderrMu.Unlock()
	switch {
	case out.err != nil:
		return out.res, &agenttools.Error{
			Code:    agenttools.CodeInvalidArgument,
			Message: "refused the archive from the sandbox: " + out.err.Error(),
			Hint:    "nothing was written outside " + dest + "; entries before the refused one were kept",
		}
	case waitErr != nil:
		return out.res, agenttools.Classify(waitErr)
	case exit.Code == noTarExit:
		return out.res, &agenttools.Error{
			Code:    agenttools.CodeUnsupportedRuntime,
			Message: "the sandbox image has no tar, which cp -r needs to copy a folder",
			Hint:    "install tar in the image, or copy the files one at a time with aerolvm cp",
		}
	case exit.Code != 0 || exit.Signal != "":
		if message == "" {
			message = fmt.Sprintf("tar exited with code %d", exit.Code)
		}
		return out.res, &agenttools.Error{Code: agenttools.CodeInvalidArgument, Message: "tar in the sandbox failed: " + message}
	}
	return out.res, nil
}

func (a *app) reportDirCopy(c *commonFlags, src, dst string, res *safetar.Result) int {
	if c.json {
		out := map[string]any{"source": src, "destination": dst, "recursive": true}
		if res != nil {
			out["entries"], out["bytes"] = res.Entries, res.Bytes
		}
		a.printJSON(out)
		return exitOK
	}
	if res != nil {
		a.note("copied %d entries (%d bytes): %s -> %s", res.Entries, res.Bytes, src, dst)
		return exitOK
	}
	a.note("copied folder: %s -> %s", src, dst)
	return exitOK
}
