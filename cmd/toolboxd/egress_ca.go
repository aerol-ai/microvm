package main

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// systemTrustStores are where common images keep their CA bundle.
var systemTrustStores = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL, Amazon Linux
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // Alpine (LibreSSL), others
}

// buildEgressCABundle writes the bundle TLS clients in an inspect sandbox
// trust (plans/egress-domain-filtering.md §5.9, P3-1): the image's own trust
// store, so its custom CAs keep working, plus the egress gateway's CA, which
// sandboxd mounted read-only. sandboxd points SSL_CERT_FILE and friends at
// it, so it is written before the user command or any exec can run. A
// sandbox without inspect rules has neither variable and nothing happens.
func buildEgressCABundle(logger *slog.Logger, stores []string) {
	caPath := strings.TrimSpace(os.Getenv("AEROLVM_EGRESS_CA"))
	bundlePath := strings.TrimSpace(os.Getenv("AEROLVM_EGRESS_CA_BUNDLE"))
	if caPath == "" || bundlePath == "" {
		return
	}
	if err := writeEgressCABundle(caPath, bundlePath, stores); err != nil {
		// TLS to inspected hosts fails closed without it; say why.
		logger.Error("egress CA bundle not written; inspected hosts will fail TLS verification", "error", err)
	}
}

func writeEgressCABundle(caPath, bundlePath string, stores []string) error {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read the egress CA: %w", err)
	}
	var store []byte
	for _, p := range stores {
		if b, err := os.ReadFile(p); err == nil && len(bytes.TrimSpace(b)) > 0 {
			store = b
			break
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read the image trust store %s: %w", p, err)
		}
	}
	var out bytes.Buffer
	out.Write(store)
	if len(store) > 0 && !bytes.HasSuffix(store, []byte("\n")) {
		out.WriteByte('\n')
	}
	out.Write(ca)
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		return fmt.Errorf("egress CA bundle: %w", err)
	}
	tmp := bundlePath + ".tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return fmt.Errorf("egress CA bundle: %w", err)
	}
	return os.Rename(tmp, bundlePath)
}
