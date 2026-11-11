package daemon

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"os"
	"time"
)

// tlsCertWatchInterval paces the certificate check: cert-manager renews
// well before expiry, and the kubelet updates a mounted Secret within about
// a minute, so a check a minute is ample.
var tlsCertWatchInterval = time.Minute

// watchTLSCertificate makes Caddy reload its file-loaded certificates each
// time the certificate at path changes (C25): cert-manager renews the
// sandbox-link wildcard into a Secret mounted into the edge container and
// this one, and Caddy reads such files only when its TLS app starts. A
// failed reload is tried again at the next check. The certificate is
// compared by content, since the kubelet replaces a Secret's files by
// swapping a link, not by writing them.
func watchTLSCertificate(ctx context.Context, path string, reload func(context.Context) (bool, error), logger *slog.Logger) {
	last, err := fileDigest(path)
	if err != nil {
		logger.Warn("tls certificate watch: cannot read the certificate yet", "path", path, "error", err)
	}
	t := time.NewTicker(tlsCertWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cur, err := fileDigest(path)
		if err != nil {
			logger.Warn("tls certificate watch: cannot read the certificate", "path", path, "error", err)
			continue
		}
		if cur == last {
			continue
		}
		reloaded, err := reload(ctx)
		if err != nil {
			logger.Warn("tls certificate changed but caddy did not reload it; trying again", "path", path, "error", err)
			continue
		}
		last = cur
		logger.Info("tls certificate changed; caddy reloaded its certificates", "path", path, "reloaded", reloaded)
	}
}

func fileDigest(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
