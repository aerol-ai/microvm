package cluster

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// PublicWasmMigratePath is the operator-facing live-migration endpoint (§4.4).
	PublicWasmMigratePath = "/v1/cluster/wasm-migrate"
	// PublicInternalWasmMigratePath prefixes per-sandbox internal export/import routes.
	PublicInternalWasmMigratePath = "/v1/cluster/internal/wasm-migrate/"

	// WasmMigrateCloneGenHeader carries the §4.8 clone-generation token on export.
	WasmMigrateCloneGenHeader = "X-Aerol-Clone-Generation"
	// WasmMigrateTarMediaType is the streamed mem.snap tarball content type.
	WasmMigrateTarMediaType = "application/vnd.aerolvm.wasm-migrate.v1+tar"
)

func wasmMigrateExportPath(sandboxID string) string {
	return PublicInternalWasmMigratePath + url.PathEscape(sandboxID) + "/export"
}

func wasmMigrateImportPath(sandboxID string) string {
	return PublicInternalWasmMigratePath + url.PathEscape(sandboxID) + "/import"
}

// StreamWasmMigrateExport pulls a mem.snap tarball from owner into w.
func StreamWasmMigrateExport(ctx context.Context, c Client, owner OwnerInfo, sandboxID string, w io.Writer) (cloneGen string, err error) {
	if owner.IsSelf {
		return "", fmt.Errorf("cluster: export requested for self owner")
	}
	return cloneGen, wasmMigrateHTTP(ctx, c, owner.InternalURL, owner.APIURL, http.MethodGet, wasmMigrateExportPath(sandboxID), nil, w, &cloneGen)
}

// PostWasmMigrateImport pushes a mem.snap tarball to target.
func PostWasmMigrateImport(ctx context.Context, c Client, target Member, sandboxID, cloneGen string, body io.Reader) error {
	if target.NodeID == c.SelfNodeID() {
		return fmt.Errorf("cluster: import to self should be handled locally")
	}
	return wasmMigrateHTTP(ctx, c, target.InternalURL, target.APIURL, http.MethodPut, wasmMigrateImportPath(sandboxID), body, nil, &cloneGen)
}

func wasmMigrateHTTP(ctx context.Context, c Client, internalURL, apiURL, method, path string, body io.Reader, out io.Writer, cloneGen *string) error {
	client, base, err := wasmMigratePeerClient(c, internalURL, apiURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", WasmMigrateTarMediaType)
	}
	if cloneGen != nil && *cloneGen != "" && method == http.MethodPut {
		req.Header.Set(WasmMigrateCloneGenHeader, *cloneGen)
	}
	if pat := wasmMigratePAT(c); pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return statusError{status: resp.StatusCode, message: strings.TrimSpace(string(msg))}
	}
	if cloneGen != nil && method == http.MethodGet {
		*cloneGen = strings.TrimSpace(resp.Header.Get(WasmMigrateCloneGenHeader))
	}
	if out != nil {
		_, err = io.Copy(out, resp.Body)
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

type wasmMigratePATProvider interface {
	wasmMigratePAT() string
}

func wasmMigratePAT(c Client) string {
	if p, ok := c.(wasmMigratePATProvider); ok {
		return p.wasmMigratePAT()
	}
	return ""
}

type wasmMigrateHTTPProvider interface {
	wasmMigrateHTTPClient(internalURL, apiURL string) (*http.Client, string, error)
}

func wasmMigratePeerClient(c Client, internalURL, apiURL string) (*http.Client, string, error) {
	if p, ok := c.(wasmMigrateHTTPProvider); ok {
		return p.wasmMigrateHTTPClient(internalURL, apiURL)
	}
	if internalURL != "" {
		return http.DefaultClient, internalURL, nil
	}
	if apiURL == "" {
		return nil, "", fmt.Errorf("cluster: peer API URL unknown")
	}
	return http.DefaultClient, apiURL, nil
}

// ExportWasmMigrateLocal buffers export output for tests.
func ExportWasmMigrateLocal(export func(w io.Writer) (string, error)) ([]byte, string, error) {
	var buf bytes.Buffer
	gen, err := export(&buf)
	return buf.Bytes(), gen, err
}
