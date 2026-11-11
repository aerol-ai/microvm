package caddy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// C25: the certificates config is written back unchanged with
// must-revalidate, so Caddy provisions its TLS app again and reads the
// renewed files; a config with no file certificates is left alone.
func TestReloadCertificates(t *testing.T) {
	const certs = `{"load_files":[{"certificate":"/etc/aerolvm/tls/tls.crt","key":"/etc/aerolvm/tls/tls.key"}]}`
	for _, tc := range []struct {
		name         string
		getStatus    int
		getBody      string
		patchStatus  int
		wantReloaded bool
		wantErr      string
	}{
		{name: "file certificates are reloaded", getStatus: 200, getBody: certs, patchStatus: 200, wantReloaded: true},
		{name: "no TLS app yet", getStatus: 404, getBody: `{"error":"invalid traversal path"}`},
		{name: "no certificates", getStatus: 200, getBody: "null\n"},
		{name: "an empty answer", getStatus: 200, getBody: ""},
		{name: "Caddy refuses the read", getStatus: 500, getBody: "boom", wantErr: "read caddy certificates failed: 500: boom"},
		{name: "Caddy refuses the reload", getStatus: 200, getBody: certs, patchStatus: 400, wantErr: "reload caddy certificates failed: 400: loading new config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var patched string
			var revalidate string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/config/apps/tls/certificates" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				switch r.Method {
				case http.MethodGet:
					w.WriteHeader(tc.getStatus)
					_, _ = io.WriteString(w, tc.getBody)
				case http.MethodPatch:
					b, _ := io.ReadAll(r.Body)
					patched, revalidate = string(b), r.Header.Get("Cache-Control")
					w.WriteHeader(tc.patchStatus)
					if tc.patchStatus >= 400 {
						_, _ = io.WriteString(w, "loading new config: tls: open /etc/aerolvm/tls/tls.crt: no such file")
					}
				}
			}))
			defer srv.Close()
			c := New(config.Config{EnableCaddy: true, CaddyAdminURL: srv.URL, CaddyServerID: "srv0", HTTPClientTimeout: 5 * time.Second})
			reloaded, err := c.ReloadCertificates(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || reloaded != tc.wantReloaded {
				t.Fatalf("= %v %v, want %v", reloaded, err, tc.wantReloaded)
			}
			if tc.wantReloaded && (patched != certs || revalidate != "must-revalidate") {
				t.Fatalf("patched %q with Cache-Control %q", patched, revalidate)
			}
			if !tc.wantReloaded && patched != "" {
				t.Fatal("a config with nothing to reload was written")
			}
		})
	}
}

func TestReloadCertificatesUnreachable(t *testing.T) {
	c := New(config.Config{EnableCaddy: true, CaddyAdminURL: "http://127.0.0.1:1", HTTPClientTimeout: time.Second})
	if _, err := c.ReloadCertificates(context.Background()); err == nil || !strings.Contains(err.Error(), "read caddy certificates") {
		t.Fatalf("err = %v", err)
	}
}

// Transport failures at each step are errors, never a silent "reloaded".
func TestReloadCertificatesTransportFailures(t *testing.T) {
	bad := New(config.Config{EnableCaddy: true, CaddyAdminURL: "http://bad host", HTTPClientTimeout: time.Second})
	if _, err := bad.ReloadCertificates(context.Background()); err == nil {
		t.Fatal("a malformed admin URL was accepted")
	}
	hijack := func(w http.ResponseWriter, partial string) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = buf.WriteString(partial)
		_ = buf.Flush()
		_ = conn.Close()
	}
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{name: "the body is cut off", h: func(w http.ResponseWriter, r *http.Request) {
			hijack(w, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"load_files\"")
		}, want: "read caddy certificates"},
		{name: "the reload connection drops", h: func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, `{"load_files":[]}`)
				return
			}
			hijack(w, "")
		}, want: "reload caddy certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.h)
			defer srv.Close()
			c := New(config.Config{EnableCaddy: true, CaddyAdminURL: srv.URL, HTTPClientTimeout: 5 * time.Second})
			if ok, err := c.ReloadCertificates(context.Background()); err == nil || ok || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("= %v %v, want an error naming %q", ok, err, tc.want)
			}
		})
	}
}
