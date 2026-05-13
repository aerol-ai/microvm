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

func (h *handlers) toolbox(w http.ResponseWriter, r *http.Request) {
	_, sandboxID, err := h.resolveSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	path := strings.TrimPrefix(r.PathValue("path"), "/")
	switch {
	case r.Method == http.MethodGet && path == "":
		h.forwardToolbox(w, r, sandboxID, "/")
	case r.Method == http.MethodGet && path == "health":
		h.forwardToolbox(w, r, sandboxID, "/health")
	case r.Method == http.MethodGet && path == "version":
		h.forwardToolbox(w, r, sandboxID, "/version")
	case r.Method == http.MethodGet && path == "user-home-dir":
		h.userHomeDir(w, r, sandboxID)
	case r.Method == http.MethodGet && path == "workdir":
		h.workDir(w, r, sandboxID)
	case r.Method == http.MethodPost && path == "process/execute":
		h.executeCommand(w, r, sandboxID)
	case r.Method == http.MethodPost && path == "files/upload":
		h.forwardToolbox(w, r, sandboxID, "/files/upload")
	case r.Method == http.MethodGet && path == "files/download":
		h.forwardToolbox(w, r, sandboxID, "/files/download")
	case r.Method == http.MethodPost && path == "files/bulk-upload":
		h.bulkUpload(w, r, sandboxID)
	case r.Method == http.MethodPost && path == "files/bulk-download":
		h.bulkDownload(w, r, sandboxID)
	default:
		apihttp.WriteError(w, http.StatusNotImplemented, "daytona toolbox route not implemented")
	}
}

func (h *handlers) executeCommand(w http.ResponseWriter, r *http.Request, sandboxID string) {
	var req executeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid multipart form")
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)
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

	headers := http.Header{}
	headers.Set("Content-Type", multipartWriter.FormDataContentType())
	resp, err := h.sendToolboxRequest(ctx, sandboxID, http.MethodPost, "/files/upload", url.Values{"path": []string{targetPath}}, reader, headers)
	if err != nil {
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
		if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (h *handlers) sendToolboxRequest(ctx context.Context, sandboxID, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	endpoint, err := h.deps.Service.ToolboxTarget(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, err
	}
	resolved := target.ResolveReference(&url.URL{Path: path, RawQuery: query.Encode()})
	req, err := http.NewRequestWithContext(ctx, method, resolved.String(), body)
	if err != nil {
		return nil, err
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if endpoint.Token != "" {
		req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	}
	return h.httpClient.Do(req)
}

func (h *handlers) writeToolboxError(w http.ResponseWriter, err error) {
	var httpErr *toolboxHTTPError
	if errors.As(err, &httpErr) {
		apihttp.WriteError(w, httpErr.StatusCode, httpErr.Error())
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
	body, _ := io.ReadAll(resp.Body)
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
