package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// FeatureFileVerbs is the toolboxd feature (on /version) behind the file
// verbs' options: list depth and cap, the move and copy overwrite guard,
// mkdir without parents, and the copy route (plans/agent-sandbox-feature-
// parity.md, F1). An older agent ignores these options, so overwrite=false
// would overwrite; the calls that send them check first.
const FeatureFileVerbs = "files.verbs"

// Error codes toolboxd puts on file errors the SDK acts on.
const (
	codeFileNotFound = "file_not_found"
	codeFolderExists = "folder_exists"
)

// listTruncatedHeader marks a listing its entry cap cut short.
const listTruncatedHeader = "X-Toolbox-Truncated"

// fileInfoWire is toolboxd's file info with extended=true: Daytona's
// fields plus path, size_bytes and symlink_target. An agent that predates
// extended answers Daytona's fields only, so each extended field falls back.
type fileInfoWire struct {
	Name          string  `json:"name"`
	IsDir         bool    `json:"isDir"`
	Size          int64   `json:"size"`
	Mode          string  `json:"mode"`
	Permissions   string  `json:"permissions"`
	Owner         string  `json:"owner"`
	Group         string  `json:"group"`
	ModTime       string  `json:"modTime"`
	Path          string  `json:"path"`
	SizeBytes     *int64  `json:"size_bytes"`
	SymlinkTarget *string `json:"symlink_target"`
}

func (w fileInfoWire) info(fallbackPath string) sdktypes.FileInfo {
	out := sdktypes.FileInfo{
		Name: w.Name, Path: w.Path, IsDir: w.IsDir, Size: w.Size, Mode: w.Mode,
		Permissions: w.Permissions, Owner: w.Owner, Group: w.Group, ModTime: w.ModTime,
	}
	if w.SizeBytes != nil {
		out.Size = *w.SizeBytes
	}
	if out.Path == "" {
		out.Path = fallbackPath
	}
	if w.SymlinkTarget != nil {
		out.SymlinkTarget = *w.SymlinkTarget
	}
	return out
}

func (c *Client) toolboxPath(id, route string, query url.Values) string {
	path := c.versionPrefix + "/sandboxes/" + url.PathEscape(id) + "/toolbox" + route
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return path
}

// ListFiles lists a folder in the sandbox. It always sends a depth and an
// entry cap, so it needs an agent that lists files.verbs. Safe to retry.
func (c *Client) ListFiles(ctx context.Context, id, path string, opts sdktypes.ListFilesOptions) (sdktypes.FileList, error) {
	if err := c.RequireToolboxFeatures(ctx, id, FeatureFileVerbs); err != nil {
		return sdktypes.FileList{}, err
	}
	depth, limit := opts.Depth, opts.Limit
	if depth <= 0 {
		depth = 1
	}
	if limit <= 0 {
		limit = sdktypes.DefaultListLimit
	}
	query := url.Values{"path": {path}, "depth": {strconv.Itoa(depth)}, "limit": {strconv.Itoa(limit)}, "extended": {"true"}}
	var wire []fileInfoWire
	header, err := c.doJSONHeaders(ctx, http.MethodGet, c.toolboxPath(id, "/files", query), nil, &wire, retryIdempotent)
	if err != nil {
		return sdktypes.FileList{}, err
	}
	list := sdktypes.FileList{Entries: make([]sdktypes.FileInfo, 0, len(wire)), Truncated: header.Get(listTruncatedHeader) == "true"}
	for _, item := range wire {
		list.Entries = append(list.Entries, item.info(strings.TrimSuffix(path, "/")+"/"+item.Name))
	}
	return list, nil
}

// GetFileInfo describes one path, following a symlink. Safe to retry.
// extended=true only adds fields, so an older agent that ignores it still
// answers in a shape this reads; no /version check is needed.
func (c *Client) GetFileInfo(ctx context.Context, id, path string) (sdktypes.FileInfo, error) {
	var wire fileInfoWire
	if err := c.doJSON(ctx, http.MethodGet, c.toolboxPath(id, "/files/info", url.Values{"path": {path}, "extended": {"true"}}), nil, &wire); err != nil {
		return sdktypes.FileInfo{}, err
	}
	return wire.info(path), nil
}

// FileExists reports whether path exists. A missing sandbox is an error,
// not false.
func (c *Client) FileExists(ctx context.Context, id, path string) (bool, error) {
	_, err := c.GetFileInfo(ctx, id, path)
	if err == nil {
		return true, nil
	}
	if isMissingFile(err) {
		return false, nil
	}
	return false, err
}

// isMissingFile tells a missing file from a missing sandbox, which is a 404
// too. Current agents say file_not_found; older ones send no code but their
// message is the OS error, which ends "no such file or directory".
func isMissingFile(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		return false
	}
	return apiErr.Code == codeFileNotFound || (apiErr.Code == "" && strings.HasSuffix(apiErr.Message, "no such file or directory"))
}

// DeleteFile deletes a file, or a folder with Recursive. Safe to retry: a
// retry that finds the path already gone (its first attempt's reply was
// lost) counts as success.
func (c *Client) DeleteFile(ctx context.Context, id, path string, opts sdktypes.DeleteFileOptions) error {
	query := url.Values{"path": {path}}
	if opts.Recursive {
		query.Set("recursive", "true")
	}
	return c.doFileCall(ctx, http.MethodDelete, c.toolboxPath(id, "/files", query), retryIdempotent, codeFileNotFound)
}

// MakeDir makes a folder. Safe to retry: without Parents, a retry that
// finds the folder already made counts as success.
func (c *Client) MakeDir(ctx context.Context, id, path string, opts sdktypes.MakeDirOptions) error {
	query := url.Values{"path": {path}, "parents": {strconv.FormatBool(opts.Parents)}}
	if !opts.Parents {
		// An older agent ignores parents=false and makes the parents anyway.
		if err := c.RequireToolboxFeatures(ctx, id, FeatureFileVerbs); err != nil {
			return err
		}
	}
	if opts.Mode != 0 {
		query.Set("mode", octalMode(opts.Mode))
	}
	return c.doFileCall(ctx, http.MethodPost, c.toolboxPath(id, "/files/folder", query), retryIdempotent, codeFolderExists)
}

// MoveFile moves or renames source to destination. It is not safe to
// re-send after a lost reply (the first attempt may have moved it), so it
// is retried only on 429 and 503, when the server did nothing.
func (c *Client) MoveFile(ctx context.Context, id, source, destination string, opts sdktypes.MoveFileOptions) error {
	if !opts.Overwrite {
		// An older agent ignores overwrite=false and replaces the destination.
		if err := c.RequireToolboxFeatures(ctx, id, FeatureFileVerbs); err != nil {
			return err
		}
	}
	query := url.Values{"source": {source}, "destination": {destination}, "overwrite": {strconv.FormatBool(opts.Overwrite)}}
	return c.doFileCall(ctx, http.MethodPost, c.toolboxPath(id, "/files/move", query), retryUnsentOnly, "")
}

// CopyFile copies source to destination. Retried only on 429 and 503, like
// MoveFile.
func (c *Client) CopyFile(ctx context.Context, id, source, destination string, opts sdktypes.CopyFileOptions) error {
	if err := c.RequireToolboxFeatures(ctx, id, FeatureFileVerbs); err != nil {
		return err
	}
	query := url.Values{
		"source": {source}, "destination": {destination},
		"overwrite": {strconv.FormatBool(opts.Overwrite)}, "recursive": {strconv.FormatBool(opts.Recursive)},
	}
	return c.doFileCall(ctx, http.MethodPost, c.toolboxPath(id, "/files/copy", query), retryUnsentOnly, "")
}

// SearchFiles returns the paths under path whose name matches a glob such
// as "*.go". Safe to retry.
func (c *Client) SearchFiles(ctx context.Context, id, path, pattern string) ([]string, error) {
	var out struct {
		Files []string `json:"files"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.toolboxPath(id, "/files/search", url.Values{"path": {path}, "pattern": {pattern}}), nil, &out); err != nil {
		return nil, err
	}
	if out.Files == nil {
		out.Files = []string{}
	}
	return out.Files, nil
}

// FindInFiles returns the lines under path that contain text (plain text,
// not a pattern). Safe to retry.
func (c *Client) FindInFiles(ctx context.Context, id, path, text string) ([]sdktypes.FileMatch, error) {
	var out []sdktypes.FileMatch
	if err := c.doJSON(ctx, http.MethodGet, c.toolboxPath(id, "/files/find", url.Values{"path": {path}, "pattern": {text}}), nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []sdktypes.FileMatch{}
	}
	return out, nil
}

// doFileCall sends a body-less file call and discards a success reply.
func (c *Client) doFileCall(ctx context.Context, method, path string, policy retryPolicy, doneCode string) error {
	response, err := c.doWithRetryDone(ctx, policy, doneCode, func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
		if err != nil {
			return nil, err
		}
		c.addAuth(request)
		return request, nil
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return decodeError(response)
	}
	return nil
}

// octalMode is mode as toolboxd's octal mode string ("750", "1777").
func octalMode(mode os.FileMode) string {
	value := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		value |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		value |= 0o1000
	}
	return strconv.FormatUint(uint64(value), 8)
}
