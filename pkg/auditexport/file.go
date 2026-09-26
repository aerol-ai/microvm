package auditexport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// fileBackend is the log backend: NDJSON appended to one path, one write per
// batch. Like kube-apiserver's --audit-log-path it is a debugging and
// forwarding surface (a log shipper tails it), not durable storage — the
// authoritative local copy is secrets.jsonl, which already fsyncs. Path "-"
// or the stdout backend name writes to standard output.
type fileBackend struct {
	name string
	path string
	mu   sync.Mutex
	w    io.Writer
	h    *health
}

func init() {
	Register(BackendFile, func(cfg Config) (Backend, error) {
		return newFileBackend(BackendFile, cfg.File.Path, nil)
	})
	Register(BackendStdout, func(Config) (Backend, error) {
		return newFileBackend(BackendStdout, "-", os.Stdout)
	})
}

func newFileBackend(name, path string, w io.Writer) (*fileBackend, error) {
	b := &fileBackend{name: name, path: path, h: newHealth(name)}
	if path == "-" {
		if w == nil {
			w = os.Stdout
		}
		b.w = w
		return b, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit export file dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit export file open: %w", err)
	}
	b.w = f
	return b, nil
}

func (b *fileBackend) Name() string { return b.name }

func (b *fileBackend) Export(_ context.Context, batch Batch) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.w.Write(EncodeNDJSON(batch)); err != nil {
		return b.h.markErr(Temporary(err))
	}
	b.h.markOK(len(batch.Events))
	return nil
}

func (b *fileBackend) Healthy(context.Context) error {
	if b.path != "-" {
		if _, err := os.Stat(filepath.Dir(b.path)); err != nil {
			return errors.Join(b.h.Healthy(), fmt.Errorf("audit export file dir: %w", err))
		}
	}
	return b.h.Healthy()
}

// Close releases the file handle; stdout is left open.
func (b *fileBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c, ok := b.w.(io.Closer); ok && b.path != "-" {
		return c.Close()
	}
	return nil
}
