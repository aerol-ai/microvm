package auditexport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Wire headers. Receivers dedupe on Idempotency-Key (== the batch id).
const (
	HeaderBatchID     = "X-Aerol-Audit-Batch-ID"
	HeaderOffset      = "X-Aerol-Audit-Offset"
	HeaderNodeID      = "X-Aerol-Node-ID"
	HeaderSignature   = "X-Aerol-Signature"
	ContentTypeNDJSON = "application/x-ndjson"
)

// webhookBackend is the closest clone of kube-apiserver's webhook audit
// backend: one batched POST per export, authenticated at the transport
// (bearer, HMAC body signature, and/or client certificate). Redirects are
// refused so a misconfigured receiver cannot bounce evidence to a third host.
type webhookBackend struct {
	cfg    WebhookConfig
	client *http.Client
	h      *health
}

func init() {
	Register(BackendWebhook, func(cfg Config) (Backend, error) { return newWebhookBackend(cfg) })
}

func newWebhookBackend(cfg Config) (*webhookBackend, error) {
	transport, err := webhookTransport(cfg.Webhook)
	if err != nil {
		return nil, err
	}
	return &webhookBackend{
		cfg: cfg.Webhook,
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		h: newHealth(BackendWebhook),
	}, nil
}

func webhookTransport(cfg WebhookConfig) (http.RoundTripper, error) {
	if cfg.CAFile == "" && cfg.CertFile == "" {
		return http.DefaultTransport, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("audit export webhook CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("audit export webhook CA file holds no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("audit export webhook client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{TLSClientConfig: tlsCfg}, nil
	}
	t = t.Clone()
	t.TLSClientConfig = tlsCfg
	return t, nil
}

func (b *webhookBackend) Name() string { return BackendWebhook }

func (b *webhookBackend) Export(ctx context.Context, batch Batch) error {
	body := EncodeNDJSON(batch)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return b.h.markErr(err)
	}
	req.Header.Set("Content-Type", ContentTypeNDJSON)
	req.Header.Set(HeaderOffset, batch.Offset)
	req.Header.Set(HeaderNodeID, batch.NodeID)
	req.Header.Set(HeaderBatchID, batch.BatchID)
	req.Header.Set("Idempotency-Key", batch.BatchID)
	if b.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.cfg.BearerToken)
	}
	if b.cfg.HMACKey != "" {
		req.Header.Set(HeaderSignature, SignBody(b.cfg.HMACKey, body))
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return b.h.markErr(Temporary(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		b.h.markOK(len(batch.Events))
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return b.h.markErr(Temporary(fmt.Errorf("audit export webhook status %d", resp.StatusCode)))
	default:
		// 3xx (redirect refused) and 4xx are receiver-side configuration
		// problems. Still retried by the tailer — the buffer is never dropped —
		// but counted as non-temporary so the alert names the right cause.
		return b.h.markErr(fmt.Errorf("audit export webhook status %d", resp.StatusCode))
	}
}

func (b *webhookBackend) Healthy(context.Context) error { return b.h.Healthy() }

// SignBody returns the X-Aerol-Signature value for body under key.
func SignBody(key string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature is the receiver-side check, exported so a Go receiver and
// the tests share one implementation.
func VerifySignature(key string, body []byte, header string) bool {
	return hmac.Equal([]byte(SignBody(key, body)), []byte(header))
}
