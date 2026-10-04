package containerd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeAOCR is a loopback registry that behaves like AOCR for `cluster/*`:
// every registry request without the granted bearer gets a Bearer challenge,
// and the token endpoint refuses anonymous callers with 401. That reproduces
// the live failure ("failed to fetch anonymous token: ... 401") exactly, and
// lets a test read back which credential containerd's real resolver presented
// on the wire — the only proof the PAT reached the pull, not just a helper.
type fakeAOCR struct {
	srv *httptest.Server

	mu         sync.Mutex
	user, pass string // last credential presented to the token endpoint
	anonymous  int    // token requests that carried no credential
	authorized int    // manifest requests that carried the granted bearer
}

const fakeAOCRToken = "granted-bearer"

func newFakeAOCR(t *testing.T) *fakeAOCR {
	t.Helper()
	f := &fakeAOCR{}
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}`)
	sum := sha256.Sum256(manifest)
	manifestDigest := "sha256:" + hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		var user, pass string
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			user, pass = r.PostForm.Get("username"), r.PostForm.Get("password")
		} else if u, p, ok := r.BasicAuth(); ok {
			user, pass = u, p
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if user == "" {
			f.anonymous++
			http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
			return
		}
		f.user, f.pass = user, pass
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token":%q}`, fakeAOCRToken, fakeAOCRToken)
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeAOCRToken {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake-aocr"`, f.srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.authorized++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", manifestDigest)
		w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(manifest)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// host is the registry host as it appears in refs (127.0.0.1:port), which
// containerd's resolver treats as plain-HTTP loopback.
func (f *fakeAOCR) host() string { return strings.TrimPrefix(f.srv.URL, "http://") }

func (f *fakeAOCR) seen() (user, pass string, anonymous, authorized int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.user, f.pass, f.anonymous, f.authorized
}

// resolvingTransport is a fake containerd whose image store is always empty
// and whose Pull runs the caller's RemoteOpts through containerd's real docker
// resolver — exactly what cntr.Client.Pull does before fetching layers.
func resolvingTransport() *fakeTransport {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	tr.pullImageFn = func(ctx context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
		rc := &cntr.RemoteContext{}
		for _, o := range opts {
			if err := o(nil, rc); err != nil {
				return nil, err
			}
		}
		if rc.Resolver == nil {
			// cntr.Client.Pull's default: an anonymous resolver.
			rc.Resolver = docker.NewResolver(docker.ResolverOptions{})
		}
		if _, _, err := rc.Resolver.Resolve(ctx, ref); err != nil {
			return nil, err
		}
		return &fakeImage{name: ref}, nil
	}
	return tr
}

func writeClusterPAT(t *testing.T, token string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cluster-pat")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}
	return p
}

// TestEnsureImageAOCRClusterPullAuth is the regression test for the containerd
// cross-node create-from-snapshot 401: a nil-auth pull of an AOCR `cluster/`
// ref must present the cluster PAT, and nothing else may borrow it.
func TestEnsureImageAOCRClusterPullAuth(t *testing.T) {
	reg := newFakeAOCR(t)
	clusterRef := reg.host() + "/cluster/prod-aerolvm-us-east-1/snapshots/py-ready:latest--ttl-1h"
	patPath := writeClusterPAT(t, "cluster-pat-1\n")

	cases := []struct {
		name      string
		configure func(d *Driver)
		ref       string
		auth      *models.RegistryAuth
		wantUser  string // "" = expect an anonymous pull that AOCR rejects
		wantPass  string
	}{
		{
			name:      "AOCR cluster ref gets the cluster PAT",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{reg.host()}, "prod-aerolvm-us-east-1", patPath) },
			ref:       clusterRef,
			wantUser:  "prod-aerolvm-us-east-1",
			wantPass:  "cluster-pat-1",
		},
		{
			name:      "username-less caller auth is back-filled like nil",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{reg.host()}, "prod-aerolvm-us-east-1", patPath) },
			ref:       clusterRef,
			auth:      &models.RegistryAuth{Server: reg.host()},
			wantUser:  "prod-aerolvm-us-east-1",
			wantPass:  "cluster-pat-1",
		},
		{
			name:      "explicit user auth wins over the cluster PAT",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{reg.host()}, "prod-aerolvm-us-east-1", patPath) },
			ref:       clusterRef,
			auth:      &models.RegistryAuth{Server: reg.host(), Username: "alice", Password: "alice-pw"},
			wantUser:  "alice",
			wantPass:  "alice-pw",
		},
		{
			name:      "non-AOCR host stays anonymous",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "prod-aerolvm-us-east-1", patPath) },
			ref:       clusterRef,
		},
		{
			name:      "non-cluster repo on the AOCR host stays anonymous",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{reg.host()}, "prod-aerolvm-us-east-1", patPath) },
			ref:       reg.host() + "/acme/app:v1",
		},
		{
			name:      "empty cluster id is a no-op",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{reg.host()}, "", patPath) },
			ref:       clusterRef,
		},
		{
			name:      "empty PAT path is a no-op",
			configure: func(d *Driver) { d.ConfigureAOCRPullAuth([]string{reg.host()}, "prod-aerolvm-us-east-1", "") },
			ref:       clusterRef,
		},
		{
			name:      "never configured is anonymous",
			configure: func(*Driver) {},
			ref:       clusterRef,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, anonBefore, authBefore := reg.seen()
			d := newTestDriver(t)
			tc.configure(d)
			d.SetClient(NewTestClient("aerolvm", resolvingTransport()))

			img, err := d.ensureImage(context.Background(), d.client, tc.ref, tc.auth)
			user, pass, anon, authed := reg.seen()

			if tc.wantUser == "" {
				if err == nil || !strings.Contains(err.Error(), "failed to fetch anonymous token") {
					t.Fatalf("want AOCR's anonymous 401, got img=%v err=%v", img, err)
				}
				if anon != anonBefore+1 || authed != authBefore {
					t.Fatalf("anonymous token requests %d->%d, authorized %d->%d; want exactly one anonymous attempt", anonBefore, anon, authBefore, authed)
				}
				return
			}
			if err != nil || img == nil {
				t.Fatalf("ensureImage: img=%v err=%v", img, err)
			}
			if user != tc.wantUser || pass != tc.wantPass {
				t.Fatalf("token endpoint saw %q/%q, want %q/%q", user, pass, tc.wantUser, tc.wantPass)
			}
			if anon != anonBefore || authed <= authBefore {
				t.Fatalf("anonymous %d->%d authorized %d->%d; want an authorized manifest hit and no anonymous attempt", anonBefore, anon, authBefore, authed)
			}
		})
	}
}

// TestEnsureImageAOCRPullAuthRereadsRotatedPAT pins the rotation contract: the
// PAT is read on every cold pull, so a file write takes effect without a
// restart or reconfigure.
func TestEnsureImageAOCRPullAuthRereadsRotatedPAT(t *testing.T) {
	reg := newFakeAOCR(t)
	patPath := writeClusterPAT(t, "before-rotation")
	d := newTestDriver(t)
	d.ConfigureAOCRPullAuth([]string{reg.host()}, "c1", patPath)
	d.SetClient(NewTestClient("aerolvm", resolvingTransport()))
	ref := reg.host() + "/cluster/c1/snapshots/s:latest--ttl-1h"

	if _, err := d.ensureImage(context.Background(), d.client, ref, nil); err != nil {
		t.Fatalf("first pull: %v", err)
	}
	if _, pass, _, _ := reg.seen(); pass != "before-rotation" {
		t.Fatalf("first pull presented %q, want before-rotation", pass)
	}
	if err := os.WriteFile(patPath, []byte("after-rotation"), 0o600); err != nil {
		t.Fatalf("rotate pat: %v", err)
	}
	if _, err := d.ensureImage(context.Background(), d.client, ref, nil); err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if _, pass, _, _ := reg.seen(); pass != "after-rotation" {
		t.Fatalf("pull after rotation presented %q, want after-rotation", pass)
	}
}

// TestEnsureImageAOCRPullAuthUnreadablePAT matches the docker engine's policy
// (warn, then attempt anonymously) and adds what docker lacks: the failed
// pull's error names the PAT file, so the create does not surface only AOCR's
// opaque anonymous-token 401.
func TestEnsureImageAOCRPullAuthUnreadablePAT(t *testing.T) {
	reg := newFakeAOCR(t)
	missing := filepath.Join(t.TempDir(), "cluster-pat-missing")
	d := newTestDriver(t)
	d.ConfigureAOCRPullAuth([]string{reg.host()}, "c1", missing)
	d.SetClient(NewTestClient("aerolvm", resolvingTransport()))

	_, err := d.ensureImage(context.Background(), d.client, reg.host()+"/cluster/c1/snapshots/s:latest", nil)
	if err == nil {
		t.Fatal("want pull failure with an unreadable PAT")
	}
	msg := err.Error()
	for _, want := range []string{"failed to fetch anonymous token", "AOCR cluster pull auth unavailable", missing} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error %v does not wrap the PAT read cause", err)
	}
	if _, _, anon, _ := reg.seen(); anon != 1 {
		t.Fatalf("anonymous attempts = %d, want 1 (same fallback as the docker engine)", anon)
	}
}

// TestEnsureImageAOCRPullAuthUnreadablePATPublicImage: the PAT failure only
// annotates a failed pull; if the anonymous attempt succeeds, the create must
// not fail because of it.
func TestEnsureImageAOCRPullAuthUnreadablePATPublicImage(t *testing.T) {
	tr := newFakeTransport()
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) { return nil, errdefs.ErrNotFound }
	var gotResolver bool
	tr.pullImageFn = func(_ context.Context, ref string, opts ...cntr.RemoteOpt) (cntr.Image, error) {
		rc := &cntr.RemoteContext{}
		for _, o := range opts {
			_ = o(nil, rc)
		}
		gotResolver = rc.Resolver != nil
		return &fakeImage{name: ref}, nil
	}
	d := newTestDriver(t)
	d.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", filepath.Join(t.TempDir(), "missing"))
	d.SetClient(NewTestClient("aerolvm", tr))

	img, err := d.ensureImage(context.Background(), d.client, "aocr.aerol.ai/cluster/c1/snapshots/s:latest", nil)
	if err != nil || img == nil {
		t.Fatalf("ensureImage: img=%v err=%v", img, err)
	}
	if gotResolver {
		t.Fatal("an unreadable PAT must leave the pull anonymous, not install a credential resolver")
	}
}

// TestPullAuthForNilLoggerDriver guards the zero-value Driver some tests and
// callers build without New: the warning path must not dereference a nil
// logger.
func TestPullAuthForNilLoggerDriver(t *testing.T) {
	d := &Driver{}
	d.ConfigureAOCRPullAuth([]string{"aocr.aerol.ai"}, "c1", filepath.Join(t.TempDir(), "missing"))
	got, err := d.pullAuthFor("aocr.aerol.ai/cluster/c1/snapshots/s:latest", nil)
	if got != nil || err == nil {
		t.Fatalf("pullAuthFor = %+v, %v; want nil auth and the PAT read error", got, err)
	}
}
