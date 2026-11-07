package microvm

import (
	"context"
	"io"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// File calls beyond upload and download (plans/agent-sandbox-feature-
// parity.md, F1). They need a sandbox whose agent is current: one that
// predates them fails closed with ErrUnsupportedFeature rather than
// ignoring a safety option such as the move overwrite guard. WASM and V8
// isolate sandboxes answer them with a 501.
//
// Retries: ListFiles, GetFileInfo, FileExists, SearchFiles, FindInFiles,
// DeleteFile and MakeDir are safe to re-send and retry on 421, 429, 502,
// 503 and 504 (a retried delete or mkdir whose work is already done counts
// as success). MoveFile and CopyFile retry only on 429 and 503.

// ListFiles lists a folder. The zero options list one level, up to
// sdktypes.DefaultListLimit entries; FileList.Truncated says more exist.
func (s *Sandbox) ListFiles(ctx context.Context, path string, opts sdktypes.ListFilesOptions) (sdktypes.FileList, error) {
	return s.client.inner.ListFiles(ctx, s.ID, path, opts)
}

// GetFileInfo describes one path. A symlink is followed.
func (s *Sandbox) GetFileInfo(ctx context.Context, path string) (sdktypes.FileInfo, error) {
	return s.client.inner.GetFileInfo(ctx, s.ID, path)
}

// FileExists reports whether path exists in the sandbox.
func (s *Sandbox) FileExists(ctx context.Context, path string) (bool, error) {
	return s.client.inner.FileExists(ctx, s.ID, path)
}

// DeleteFile deletes a file, or a folder and its contents with Recursive.
func (s *Sandbox) DeleteFile(ctx context.Context, path string, opts sdktypes.DeleteFileOptions) error {
	return s.client.inner.DeleteFile(ctx, s.ID, path, opts)
}

// MakeDir makes a folder; with Parents, like mkdir -p.
func (s *Sandbox) MakeDir(ctx context.Context, path string, opts sdktypes.MakeDirOptions) error {
	return s.client.inner.MakeDir(ctx, s.ID, path, opts)
}

// MoveFile moves or renames a file or folder. Without Overwrite, an
// existing destination is a 409 conflict (errors.Is(err, ErrConflict)).
func (s *Sandbox) MoveFile(ctx context.Context, source, destination string, opts sdktypes.MoveFileOptions) error {
	return s.client.inner.MoveFile(ctx, s.ID, source, destination, opts)
}

// CopyFile copies a file, or a folder with Recursive.
func (s *Sandbox) CopyFile(ctx context.Context, source, destination string, opts sdktypes.CopyFileOptions) error {
	return s.client.inner.CopyFile(ctx, s.ID, source, destination, opts)
}

// SearchFiles returns the paths under path whose name matches a glob such
// as "*.py".
func (s *Sandbox) SearchFiles(ctx context.Context, path, pattern string) ([]string, error) {
	return s.client.inner.SearchFiles(ctx, s.ID, path, pattern)
}

// FindInFiles returns each line under path that contains text.
func (s *Sandbox) FindInFiles(ctx context.Context, path, text string) ([]sdktypes.FileMatch, error) {
	return s.client.inner.FindInFiles(ctx, s.ID, path, text)
}

// UploadDir copies the local folder localDir into remoteDir in the sandbox,
// made if missing (a gzipped tar the sandbox unpacks safely: no entry can
// land outside remoteDir). Symlinks are sent as links and hard-linked files
// as separate files; devices, pipes and sockets are skipped. It is sent
// once and never retried. It needs an agent that lists files.extract.
func (s *Sandbox) UploadDir(ctx context.Context, localDir, remoteDir string) error {
	return s.client.inner.UploadDir(ctx, s.ID, localDir, remoteDir)
}

// DownloadFileWithOptions reads a whole file, refusing one larger than
// opts.MaxBytes with ErrFileTooLarge. It retries like DownloadFile.
func (s *Sandbox) DownloadFileWithOptions(ctx context.Context, targetPath string, opts sdktypes.DownloadFileOptions) ([]byte, error) {
	return s.client.inner.DownloadFileWithOptions(ctx, s.ID, targetPath, opts)
}

// DownloadFileStreamWithOptions is DownloadFileStream with a size limit:
// the read that passes opts.MaxBytes fails with ErrFileTooLarge.
func (s *Sandbox) DownloadFileStreamWithOptions(ctx context.Context, targetPath string, opts sdktypes.DownloadFileOptions) (io.ReadCloser, error) {
	return s.client.inner.DownloadFileStreamWithOptions(ctx, s.ID, targetPath, opts)
}
