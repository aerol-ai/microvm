package caddy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// ReloadCertificates makes Caddy read the TLS certificates its config loads
// from files again (C25 in plans/kubernetes-v2-architecture.md). On
// Kubernetes, cert-manager renews the sandbox-link wildcard into a Secret
// mounted read-only into the edge container, and the Caddyfile names those
// files; Caddy reads them only when its TLS app is provisioned, so a renewal
// would otherwise go unused until a restart. Writing the certificates config
// back unchanged with Cache-Control: must-revalidate makes Caddy apply it
// anyway (it skips an unchanged config otherwise), which provisions the TLS
// app again and reads the files fresh. A config that loads no certificates
// from files (404 or null) has nothing to reload.
func (c *Client) ReloadCertificates(ctx context.Context) (bool, error) {
	target := c.baseURL + "/config/apps/tls/certificates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.do(req)
	if err != nil {
		return false, fmt.Errorf("read caddy certificates: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return false, fmt.Errorf("read caddy certificates: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode >= 400:
		return false, caddyErr("read caddy certificates", resp.StatusCode, string(bytes.TrimSpace(body)))
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false, nil
	}
	// The same target and context built the GET above, so this cannot fail.
	req, _ = http.NewRequestWithContext(ctx, http.MethodPatch, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "must-revalidate")
	resp, err = c.do(req)
	if err != nil {
		return false, fmt.Errorf("reload caddy certificates: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, caddyErrDetailMax))
		return false, caddyErr("reload caddy certificates", resp.StatusCode, string(bytes.TrimSpace(detail)))
	}
	return true, nil
}
