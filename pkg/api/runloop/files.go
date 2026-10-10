package runloop

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// maxUploadBytes matches toolboxd's default SB_UPLOAD_MAX_BYTES, so the
// facade never accepts an upload the toolbox would then refuse.
const maxUploadBytes = 256 << 20

// resolvePath anchors a Runloop path, which is relative to the user's home
// directory, to an absolute one the toolbox can open. toolboxd itself
// resolves relative paths against its own working directory.
func (h *handlers) resolvePath(ctx context.Context, devboxID, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", badRequest("path is required")
	}
	if strings.HasPrefix(p, "/") {
		return path.Clean(p), nil
	}
	home, err := h.homeDir(ctx, devboxID)
	if err != nil {
		return "", err
	}
	p = strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/")
	return path.Join(home, p), nil
}

// homeDir asks the toolbox for $HOME once per devbox; it cannot change
// for the devbox's lifetime.
func (h *handlers) homeDir(ctx context.Context, devboxID string) (string, error) {
	if cached, ok := h.homes.Load(devboxID); ok {
		return cached.(string), nil
	}
	res, err := h.runOneShot(ctx, devboxID, `printf %s "$HOME"`)
	if err != nil {
		return "", err
	}
	home := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 || !strings.HasPrefix(home, "/") {
		return "", errors.New("could not resolve the devbox home directory")
	}
	h.homes.Store(devboxID, home)
	return home, nil
}

func (h *handlers) readFileContents(w http.ResponseWriter, r *http.Request, devboxID string) {
	var req readFileRequest
	if !decodeBody(w, r, &req) {
		return
	}
	h.serveFile(w, r, devboxID, req.FilePath, "text/plain; charset=utf-8")
}

func (h *handlers) downloadFile(w http.ResponseWriter, r *http.Request, devboxID string) {
	var req downloadFileRequest
	if !decodeBody(w, r, &req) {
		return
	}
	h.serveFile(w, r, devboxID, req.Path, "application/octet-stream")
}

// serveFile streams a file's bytes unwrapped. read_file_contents must not
// JSON-encode the text: Python returns the body verbatim, so a JSON string
// would reach the caller with its quotes and escapes.
func (h *handlers) serveFile(w http.ResponseWriter, r *http.Request, devboxID, filePath, contentType string) {
	target, err := h.resolvePath(r.Context(), devboxID, filePath)
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	resp, err := h.deps.Service.RoundTripToolbox(r.Context(), devboxID, http.MethodGet, "/files/download", url.Values{"path": {target}}, nil, nil)
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		h.writeToolboxError(w, readToolboxError(resp))
		return
	}
	w.Header().Set("Content-Type", contentType)
	if length := resp.Header.Get("Content-Length"); length != "" {
		w.Header().Set("Content-Length", length)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

func (h *handlers) writeFileContents(w http.ResponseWriter, r *http.Request, devboxID string) {
	var req writeFileRequest
	if !decodeBody(w, r, &req) {
		return
	}
	target, err := h.resolvePath(r.Context(), devboxID, req.FilePath)
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	if err := h.uploadToToolbox(r.Context(), devboxID, target, path.Base(target), strings.NewReader(req.Contents)); err != nil {
		h.writeToolboxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, executionDetailView{DevboxID: devboxID, ExitStatus: 0, Stdout: "", Stderr: ""})
}

// uploadFile takes the SDK's multipart form (fields `path` and `file`).
// Nothing pins the part order — `file` may come before `path` — so the
// form is parsed whole rather than streamed; parts past 32 MiB spool to
// temp files instead of memory.
func (h *handlers) uploadFile(w http.ResponseWriter, r *http.Request, devboxID string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid multipart form (or too large)")
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	target, err := h.resolvePath(r.Context(), devboxID, r.FormValue("path"))
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		WriteError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()
	if err := h.uploadToToolbox(r.Context(), devboxID, target, header.Filename, file); err != nil {
		h.writeToolboxError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// uploadToToolbox streams content to toolboxd's multipart upload without
// buffering it in sandboxd.
func (h *handlers) uploadToToolbox(ctx context.Context, devboxID, target, filename string, content io.Reader) error {
	reader, writer := io.Pipe()
	form := multipart.NewWriter(writer)
	headers := http.Header{}
	headers.Set("Content-Type", form.FormDataContentType())
	errCh := make(chan error, 1)
	go func() {
		part, err := form.CreateFormFile("file", filename)
		if err == nil {
			_, err = io.Copy(part, content)
		}
		if closeErr := form.Close(); err == nil {
			err = closeErr
		}
		_ = writer.CloseWithError(err)
		errCh <- err
	}()
	resp, err := h.deps.Service.RoundTripToolbox(ctx, devboxID, http.MethodPost, "/files/upload", url.Values{"path": {target}}, reader, headers)
	if err != nil {
		_ = reader.CloseWithError(err)
		<-errCh
		return err
	}
	defer resp.Body.Close()
	if writeErr := <-errCh; writeErr != nil {
		return writeErr
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return readToolboxError(resp)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
