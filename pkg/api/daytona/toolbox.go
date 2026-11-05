package daytona

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

var bulkUploadField = regexp.MustCompile(`^files\[(\d+)\]\.(path|file)$`)

type toolboxHTTPError struct {
	StatusCode int
	Message    string
}

func (e *toolboxHTTPError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return http.StatusText(e.StatusCode)
}

// toolboxRouteKind says how a Daytona toolbox route reaches the sandbox.
type toolboxRouteKind int

const (
	// toolboxForward sends the request to the same toolboxd path.
	toolboxForward toolboxRouteKind = iota
	// toolboxProxy reverse-proxies it, so WebSocket upgrades pass through.
	toolboxProxy
	// toolboxLocal is handled here; upstream lists the toolboxd calls it makes.
	toolboxLocal
)

// toolboxRoute is one Daytona toolbox route. The table below is both the
// dispatch and the inventory the toolboxd route test (X2 in
// plans/agent-sandbox-feature-parity.md) checks, so a route cannot be
// forwarded to a toolboxd path that does not exist without failing make test.
type toolboxRoute struct {
	method   string // empty matches any method
	path     string // without the leading slash
	prefix   bool   // path is a prefix
	bare     bool   // a prefix route that also matches the path without its trailing slash
	kind     toolboxRouteKind
	local    func(h *handlers, w http.ResponseWriter, r *http.Request, sandboxID string)
	upstream []ToolboxCall
}

func (r toolboxRoute) matches(method, path string) bool {
	if r.method != "" && r.method != method {
		return false
	}
	if r.prefix {
		return strings.HasPrefix(path, r.path) || (r.bare && path == strings.TrimSuffix(r.path, "/"))
	}
	return path == r.path
}

// ToolboxCall is one toolboxd request a facade makes: a method (empty for
// any) and a path, which is a prefix when Prefix is set.
type ToolboxCall struct {
	Method string
	Path   string
	Prefix bool
}

var toolboxRoutes = []toolboxRoute{
	{method: http.MethodGet, path: "", kind: toolboxForward},
	{method: http.MethodGet, path: "health", kind: toolboxForward},
	{method: http.MethodGet, path: "version", kind: toolboxForward},
	{method: http.MethodGet, path: "user-home-dir", kind: toolboxLocal, local: (*handlers).userHomeDir,
		upstream: []ToolboxCall{{Method: http.MethodPost, Path: "/process/execute"}}},
	// The Daytona SDK's InfoApi.getWorkDir calls /work-dir (hyphenated); the
	// legacy facade route was /workdir. Both stay so older clients work.
	{method: http.MethodGet, path: "workdir", kind: toolboxLocal, local: (*handlers).workDir,
		upstream: []ToolboxCall{{Method: http.MethodPost, Path: "/process/execute"}}},
	{method: http.MethodGet, path: "work-dir", kind: toolboxLocal, local: (*handlers).workDir,
		upstream: []ToolboxCall{{Method: http.MethodPost, Path: "/process/execute"}}},
	{method: http.MethodPost, path: "process/execute", kind: toolboxLocal, local: (*handlers).executeCommand,
		upstream: []ToolboxCall{{Method: http.MethodPost, Path: "/process/execute"}}},
	{method: http.MethodPost, path: "process/code-run", kind: toolboxForward},
	// Session log/PTY streams upgrade to WebSocket, so sessions ride the
	// reverse proxy; plain-HTTP session requests ride it without harm.
	{path: "process/session/", prefix: true, bare: true, kind: toolboxProxy},
	// /process/interpreter/execute is a WebSocket stream; the context
	// endpoints are plain HTTP. The shipped toolboxd answers this prefix with
	// 501 (daytona_code_run.go); custom toolbox builds can implement it.
	{path: "process/interpreter/", prefix: true, kind: toolboxProxy},
	// /process/pty (bare) covers list/create; /process/pty/{id}/connect is
	// the WebSocket stream.
	{path: "process/pty/", prefix: true, bare: true, kind: toolboxProxy},
	{method: http.MethodGet, path: "files", kind: toolboxForward},
	{method: http.MethodDelete, path: "files", kind: toolboxForward},
	{method: http.MethodPost, path: "files/folder", kind: toolboxForward},
	{method: http.MethodPost, path: "files/replace", kind: toolboxForward},
	{method: http.MethodPost, path: "files/permissions", kind: toolboxForward},
	{method: http.MethodGet, path: "files/info", kind: toolboxForward},
	{method: http.MethodPost, path: "files/upload", kind: toolboxForward},
	{method: http.MethodGet, path: "files/download", kind: toolboxForward},
	{method: http.MethodPost, path: "files/move", kind: toolboxForward},
	{method: http.MethodGet, path: "files/search", kind: toolboxForward},
	{method: http.MethodGet, path: "files/find", kind: toolboxForward},
	{method: http.MethodPost, path: "files/bulk-upload", kind: toolboxLocal, local: (*handlers).bulkUpload,
		upstream: []ToolboxCall{{Method: http.MethodPost, Path: "/files/upload"}}},
	{method: http.MethodPost, path: "files/bulk-download", kind: toolboxLocal, local: (*handlers).bulkDownload,
		upstream: []ToolboxCall{{Method: http.MethodGet, Path: "/files/download"}}},
	{path: "git/", prefix: true, kind: toolboxForward},
	// Language-server calls pass through; toolboxd answers them with a clear
	// 501 because AerolVM has no language servers (plan R5).
	{path: "lsp/", prefix: true, kind: toolboxForward},
}

// ToolboxCalls lists every toolboxd request this facade can make, derived
// from the dispatch table above.
func ToolboxCalls() []ToolboxCall {
	calls := make([]ToolboxCall, 0, len(toolboxRoutes))
	for _, route := range toolboxRoutes {
		if route.kind == toolboxLocal {
			calls = append(calls, route.upstream...)
			continue
		}
		calls = append(calls, ToolboxCall{Method: route.method, Path: "/" + route.path, Prefix: route.prefix})
		if route.bare {
			calls = append(calls, ToolboxCall{Method: route.method, Path: "/" + strings.TrimSuffix(route.path, "/")})
		}
	}
	return calls
}

// Guest-controlled toolbox responses and client uploads are bounded so a
// sandbox or a caller cannot exhaust the daemon's memory or temp disk (S11).
// The JSON and upload caps mirror the Runloop facade.
const (
	maxToolboxJSONBytes  = 64 << 20  // a command's JSON response
	maxToolboxErrorBytes = 4 << 10   // a toolbox error body
	maxBulkUploadBytes   = 256 << 20 // a whole multipart upload
)

func (h *handlers) toolbox(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	path := normalizeToolboxPath(r.PathValue("path"))
	for _, route := range toolboxRoutes {
		if !route.matches(r.Method, path) {
			continue
		}
		switch route.kind {
		case toolboxForward:
			h.forwardToolbox(w, r, sandboxID, "/"+path)
		case toolboxProxy:
			h.proxyToolbox(w, r, sandboxID, "/"+path)
		default:
			route.local(h, w, r, sandboxID)
		}
		return
	}
	apihttp.WriteError(w, http.StatusNotImplemented, "daytona toolbox route not implemented")
}

func normalizeToolboxPath(path string) string {
	trimmed := strings.Trim(strings.TrimSpace(path), "/")
	if trimmed == "toolbox" {
		return ""
	}
	if strings.HasPrefix(trimmed, "toolbox/") {
		return strings.TrimPrefix(trimmed, "toolbox/")
	}
	return trimmed
}

func (h *handlers) executeCommand(w http.ResponseWriter, r *http.Request, sandboxID string) {
	var req executeRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	result, err := h.runToolboxCommand(r.Context(), sandboxID, models.ExecRequest{
		Command:        req.Command,
		WorkDir:        strings.TrimSpace(valueOrEmpty(req.Cwd)),
		Env:            cloneStringMap(mapValue(req.Envs)),
		TimeoutSeconds: int(int32Value(req.Timeout, 0)),
	})
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	value := result.Stdout
	if value == "" {
		value = result.Stderr
	}
	exitCode := int32(result.ExitCode)
	apihttp.WriteJSON(w, http.StatusOK, executeResponse{ExitCode: &exitCode, Result: value})
}

func (h *handlers) userHomeDir(w http.ResponseWriter, r *http.Request, sandboxID string) {
	dir, err := h.runToolboxString(r.Context(), sandboxID, `printf %s "$HOME"`)
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, dirResponse{Dir: dir})
}

func (h *handlers) workDir(w http.ResponseWriter, r *http.Request, sandboxID string) {
	dir, err := h.runToolboxString(r.Context(), sandboxID, "pwd")
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, dirResponse{Dir: dir})
}

func (h *handlers) bulkUpload(w http.ResponseWriter, r *http.Request, sandboxID string) {
	// Cap the whole upload so a client cannot fill the daemon's memory or
	// temp disk during the request (S11).
	r.Body = http.MaxBytesReader(w, r.Body, maxBulkUploadBytes)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid multipart form (or too large)")
		return
	}

	type uploadFile struct {
		path string
		file *multipart.FileHeader
	}
	files := map[string]*uploadFile{}
	for key, values := range r.MultipartForm.Value {
		match := bulkUploadField.FindStringSubmatch(key)
		if len(match) != 3 || match[2] != "path" || len(values) == 0 {
			continue
		}
		entry := files[match[1]]
		if entry == nil {
			entry = &uploadFile{}
			files[match[1]] = entry
		}
		entry.path = strings.TrimSpace(values[0])
	}
	for key, values := range r.MultipartForm.File {
		match := bulkUploadField.FindStringSubmatch(key)
		if len(match) != 3 || match[2] != "file" || len(values) == 0 {
			continue
		}
		entry := files[match[1]]
		if entry == nil {
			entry = &uploadFile{}
			files[match[1]] = entry
		}
		entry.file = values[0]
	}

	if len(files) == 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "no files provided")
		return
	}

	for _, entry := range files {
		if entry == nil || entry.path == "" || entry.file == nil {
			apihttp.WriteError(w, http.StatusBadRequest, "each uploaded file must include files[n].path and files[n].file")
			return
		}
		if err := h.uploadSingleFile(r.Context(), sandboxID, entry.path, entry.file); err != nil {
			h.writeToolboxError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handlers) bulkDownload(w http.ResponseWriter, r *http.Request, sandboxID string) {
	var req filesDownloadRequest
	if err := apihttp.DecodeJSON(w, r, &req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Paths) == 0 {
		apihttp.WriteError(w, http.StatusBadRequest, "paths is required")
		return
	}

	writer := multipart.NewWriter(w)
	w.Header().Set("Content-Type", writer.FormDataContentType())
	w.WriteHeader(http.StatusOK)

	for _, targetPath := range req.Paths {
		resp, err := h.sendToolboxRequest(r.Context(), sandboxID, http.MethodGet, "/files/download", url.Values{"path": []string{targetPath}}, nil, nil)
		if err != nil {
			h.writeMultipartErrorPart(writer, errorPayload(err))
			continue
		}

		if resp.StatusCode >= http.StatusMultipleChoices {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			h.writeMultipartErrorPart(writer, responseErrorPayload(resp.StatusCode, body))
			continue
		}

		headers := textproto.MIMEHeader{
			"Content-Disposition": []string{fmt.Sprintf(`form-data; name="file"; filename=%q`, filepath.Base(targetPath))},
			"Content-Type":        []string{"application/octet-stream"},
		}
		if resp.ContentLength >= 0 {
			headers.Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
		}
		part, err := writer.CreatePart(headers)
		if err == nil {
			_, _ = io.Copy(part, resp.Body)
		}
		_ = resp.Body.Close()
	}
	_ = writer.Close()
}

func (h *handlers) writeMultipartErrorPart(writer *multipart.Writer, body []byte) {
	if len(body) == 0 {
		body = responseErrorPayload(http.StatusBadGateway, nil)
	}
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{`form-data; name="error"`},
		"Content-Type":        []string{"application/json"},
	})
	if err == nil {
		_, _ = part.Write(body)
	}
}

func (h *handlers) uploadSingleFile(ctx context.Context, sandboxID, targetPath string, fileHeader *multipart.FileHeader) error {
	file, err := fileHeader.Open()
	if err != nil {
		return err
	}
	defer file.Close()

	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	headers := http.Header{}
	headers.Set("Content-Type", multipartWriter.FormDataContentType())

	errCh := make(chan error, 1)
	go func() {
		part, err := multipartWriter.CreateFormFile("file", fileHeader.Filename)
		if err == nil {
			_, err = io.Copy(part, file)
		}
		closeErr := multipartWriter.Close()
		if err == nil {
			err = closeErr
		}
		_ = writer.CloseWithError(err)
		errCh <- err
	}()

	resp, err := h.deps.Service.RoundTripToolbox(ctx, sandboxID, http.MethodPost, "/files/upload", url.Values{"path": []string{targetPath}}, reader, headers)
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
		return readToolboxHTTPError(resp)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (h *handlers) runToolboxString(ctx context.Context, sandboxID, command string) (string, error) {
	result, err := h.runToolboxCommand(ctx, sandboxID, models.ExecRequest{Command: command, TimeoutSeconds: 10})
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(result.Stdout)
	if value == "" {
		value = strings.TrimSpace(result.Stderr)
	}
	return value, nil
}

func (h *handlers) runToolboxCommand(ctx context.Context, sandboxID string, req models.ExecRequest) (*models.ExecResult, error) {
	var result models.ExecResult
	statusCode, err := h.sendToolboxJSON(ctx, sandboxID, http.MethodPost, "/process/execute", nil, req, &result)
	if err != nil {
		return nil, err
	}
	if statusCode >= http.StatusMultipleChoices {
		return nil, &toolboxHTTPError{StatusCode: statusCode, Message: http.StatusText(statusCode)}
	}
	return &result, nil
}

// proxyToolbox forwards via httputil.ReverseProxy, which transparently
// negotiates Upgrade: websocket handshakes — unlike forwardToolbox, which
// reads the body fully through httpClient.Do and breaks WS streams.
func (h *handlers) proxyToolbox(w http.ResponseWriter, r *http.Request, sandboxID, path string) {
	if err := h.deps.Service.ServeToolboxReverseProxy(r.Context(), sandboxID, w, r, path); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
	}
}

func (h *handlers) forwardToolbox(w http.ResponseWriter, r *http.Request, sandboxID, path string) {
	resp, err := h.sendToolboxRequest(r.Context(), sandboxID, r.Method, path, r.URL.Query(), r.Body, r.Header.Clone())
	if err != nil {
		h.writeToolboxError(w, err)
		return
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *handlers) sendToolboxJSON(ctx context.Context, sandboxID, method, path string, query url.Values, requestBody any, responseBody any) (int, error) {
	var body io.Reader
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return 0, err
		}
		body = strings.NewReader(string(payload))
		headers.Set("Content-Type", "application/json")
	}
	resp, err := h.sendToolboxRequest(ctx, sandboxID, method, path, query, body, headers)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return resp.StatusCode, readToolboxHTTPError(resp)
	}
	if responseBody != nil {
		// The response comes from inside the sandbox; cap it so a guest
		// printing gigabytes cannot exhaust the daemon's memory (S11).
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxToolboxJSONBytes)).Decode(responseBody); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (h *handlers) sendToolboxRequest(ctx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	return h.deps.Service.RoundTripToolbox(ctx, sandboxID, method, path, query, body, headers)
}

func (h *handlers) writeToolboxError(w http.ResponseWriter, err error) {
	var httpErr *toolboxHTTPError
	if errors.As(err, &httpErr) {
		apihttp.WriteError(w, httpErr.StatusCode, httpErr.Error())
		return
	}
	// The sandbox stopped while the request waited on it: 409, as on /v1,
	// not a gateway error.
	if errors.Is(err, service.ErrSandboxStoppedMidRequest) {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if h.deps.Logger != nil {
		h.deps.Logger.Warn("daytona toolbox request failed", "error", err)
	}
	apihttp.WriteError(w, http.StatusBadGateway, "toolbox unavailable")
}

func readToolboxHTTPError(resp *http.Response) error {
	if resp == nil {
		return &toolboxHTTPError{StatusCode: http.StatusBadGateway, Message: "toolbox unavailable"}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxToolboxErrorBytes))
	message := strings.TrimSpace(string(body))
	if len(body) > 0 {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			message = strings.TrimSpace(payload.Error)
		}
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	return &toolboxHTTPError{StatusCode: resp.StatusCode, Message: message}
}

func errorPayload(err error) []byte {
	message := "toolbox unavailable"
	var httpErr *toolboxHTTPError
	if errors.As(err, &httpErr) {
		message = httpErr.Error()
	} else if err != nil && strings.TrimSpace(err.Error()) != "" {
		message = strings.TrimSpace(err.Error())
	}
	return []byte(fmt.Sprintf(`{"error":%q}`, message))
}

func responseErrorPayload(statusCode int, body []byte) []byte {
	message := strings.TrimSpace(string(body))
	if len(body) > 0 {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			message = strings.TrimSpace(payload.Error)
		}
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	return []byte(fmt.Sprintf(`{"error":%q}`, message))
}

func copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		switch http.CanonicalHeaderKey(key) {
		case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
