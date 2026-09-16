package auditexport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func sampleBatch() Batch {
	return Batch{
		NodeID:  "node-a",
		BatchID: "node-a:0:abc",
		Offset:  "0",
		Events: []json.RawMessage{
			json.RawMessage(`{"event_id":"ae-1","result":"success"}`),
			json.RawMessage(`{"event_id":"ae-2","result":"gap"}` + "\n"),
		},
		ShippedAt: time.Date(2026, 9, 11, 1, 2, 3, 0, time.UTC),
	}
}

func TestRegistryAndOpen(t *testing.T) {
	names := Names()
	for _, want := range []string{BackendNoop, BackendStdout, BackendFile, BackendWebhook, BackendS3, BackendBus} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("backend %q not registered (have %v)", want, names)
		}
	}
	if _, err := Open(Config{Backend: "nope"}); !errors.Is(err, ErrUnknownBackend) {
		t.Fatalf("unknown backend err = %v", err)
	}
	b, err := Open(Config{})
	if err != nil || !IsNoop(b) || b.Name() != BackendNoop {
		t.Fatalf("default open = %v, %v", b, err)
	}
	if err := b.Export(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if err := b.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("duplicate Register must panic")
			}
		}()
		Register(BackendNoop, func(Config) (Backend, error) { return nil, nil })
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("empty Register must panic")
			}
		}()
		Register("", nil)
	}()
	if !IsNoop(nil) {
		t.Fatal("nil backend must read as noop")
	}
}

func TestIsOffNodeBackend(t *testing.T) {
	for _, name := range []string{BackendWebhook, BackendS3, BackendBus, " S3 "} {
		if !IsOffNodeBackend(name) {
			t.Errorf("IsOffNodeBackend(%q) = false, want true", name)
		}
	}
	for _, name := range []string{BackendNoop, BackendStdout, BackendFile, "", "kinesis"} {
		if IsOffNodeBackend(name) {
			t.Errorf("IsOffNodeBackend(%q) = true, want false", name)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	cases := map[string]struct {
		cfg     Config
		wantErr string
	}{
		"noop ok":                   {cfg: Config{}},
		"stdout ok":                 {cfg: Config{Backend: " STDOUT "}},
		"file needs path":           {cfg: Config{Backend: BackendFile}, wantErr: "FILE_PATH"},
		"file ok":                   {cfg: Config{Backend: BackendFile, File: FileConfig{Path: "/tmp/x"}}},
		"webhook needs url":         {cfg: Config{Backend: BackendWebhook}, wantErr: "WEBHOOK_URL"},
		"webhook bad url":           {cfg: Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: "ftp://x"}}, wantErr: "absolute http"},
		"webhook userinfo":          {cfg: Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: "https://u:p@x/y"}}, wantErr: "userinfo"},
		"webhook half mtls":         {cfg: Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: "https://x/y", CertFile: "c"}}, wantErr: "both cert and key"},
		"webhook enterprise http":   {cfg: Config{Backend: BackendWebhook, Enterprise: true, Webhook: WebhookConfig{URL: "http://x/y", BearerToken: "t"}}, wantErr: "https"},
		"webhook enterprise noauth": {cfg: Config{Backend: BackendWebhook, Enterprise: true, Webhook: WebhookConfig{URL: "https://x/y"}}, wantErr: "BEARER_TOKEN"},
		"webhook enterprise hmac":   {cfg: Config{Backend: BackendWebhook, Enterprise: true, Webhook: WebhookConfig{URL: "https://x/y", HMACKey: "k"}}},
		"s3 needs bucket":           {cfg: Config{Backend: BackendS3}, wantErr: "S3_BUCKET"},
		"s3 bad endpoint":           {cfg: Config{Backend: BackendS3, S3: S3Config{Bucket: "b", Endpoint: "nope"}}, wantErr: "S3_ENDPOINT"},
		"s3 enterprise http":        {cfg: Config{Backend: BackendS3, Enterprise: true, S3: S3Config{Bucket: "b", Endpoint: "http://minio:9000"}}, wantErr: "https"},
		"s3 ok":                     {cfg: Config{Backend: BackendS3, S3: S3Config{Bucket: "b", Endpoint: "https://minio:9000", Prefix: "/audit/"}}},
		"bus needs topic":           {cfg: Config{Backend: BackendBus}, wantErr: "BUS_TOPIC"},
		"flush too small":           {cfg: Config{FlushInterval: time.Millisecond}, wantErr: "flush interval"},
		"batch too big":             {cfg: Config{BatchMax: 1 << 20}, wantErr: "batch max"},
		"unknown":                   {cfg: Config{Backend: "kinesis"}, wantErr: "unknown backend"},
		// Enterprise tamper-evidence needs history this node cannot silently
		// rewrite; noop/stdout/file all die with the disk.
		"noop enterprise":   {cfg: Config{Enterprise: true}, wantErr: "off-node backend"},
		"stdout enterprise": {cfg: Config{Backend: BackendStdout, Enterprise: true}, wantErr: "off-node backend"},
		"file enterprise":   {cfg: Config{Backend: BackendFile, Enterprise: true, File: FileConfig{Path: "/tmp/x"}}, wantErr: "off-node backend"},
		"bus enterprise ok": {cfg: Config{Backend: BackendBus, Enterprise: true, Bus: BusConfig{Topic: "audit"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	d := Config{S3: S3Config{Prefix: " /a/b/ "}}.WithDefaults()
	if d.Backend != BackendNoop || d.BatchMax != DefaultBatchMax || d.FlushInterval != DefaultFlushInterval || d.MaxBackoff != DefaultMaxBackoff || d.Timeout != DefaultTimeout || d.S3.Prefix != "a/b" {
		t.Fatalf("defaults = %+v", d)
	}
}

func TestBackoffGrowsCapsAndResets(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: 8 * time.Second, rand: func() float64 { return 1 }}
	var got []time.Duration
	for range 6 {
		got = append(got, b.Next())
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("attempt %d = %v, want %v (all %v)", i+1, got[i], want[i], got)
		}
	}
	if b.Attempts() != 6 {
		t.Fatalf("attempts = %d", b.Attempts())
	}
	b.Reset()
	if b.Attempts() != 0 || b.Next() != time.Second {
		t.Fatal("reset did not restart the schedule")
	}
	// Jitter floor: even rand()=0 never collapses below Base/2.
	z := &Backoff{Base: time.Second, Max: time.Minute, rand: func() float64 { return 0 }}
	if d := z.Next(); d != 500*time.Millisecond {
		t.Fatalf("jitter floor = %v", d)
	}
	// Zero-value works with defaults and real randomness within bounds.
	r := &Backoff{}
	if d := r.Next(); d < 500*time.Millisecond || d > time.Second {
		t.Fatalf("default first delay %v out of [0.5s,1s]", d)
	}
}

func TestEncodeNDJSONNormalizesTerminators(t *testing.T) {
	out := EncodeNDJSON(sampleBatch())
	lines := bytes.Split(bytes.TrimRight(out, "\n"), []byte{'\n'})
	if len(lines) != 2 || !bytes.HasSuffix(out, []byte("\n")) || bytes.Contains(out, []byte("\n\n")) {
		t.Fatalf("ndjson = %q", out)
	}
	if len(EncodeNDJSON(Batch{})) != 0 {
		t.Fatal("empty batch must encode to nothing")
	}
}

func TestFileBackendAppendsAndStdout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.ndjson")
	b, err := Open(Config{Backend: BackendFile, File: FileConfig{Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Export(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if err := b.Export(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if err := b.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, ok := b.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	if n := bytes.Count(raw, []byte{'\n'}); n != 4 {
		t.Fatalf("appended %d lines, want 4: %q", n, raw)
	}
	if exportEventsTotal.Get(BackendFile) == nil {
		t.Fatal("events metric not recorded")
	}

	var buf bytes.Buffer
	so, err := newFileBackend(BackendStdout, "-", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := so.Export(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"ae-1"`) {
		t.Fatalf("stdout backend wrote %q", buf.String())
	}
	if err := so.Close(); err != nil {
		t.Fatal(err)
	}
	if so.Name() != BackendStdout {
		t.Fatal(so.Name())
	}
	// Removing the directory makes Healthy report the problem.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := b.Healthy(context.Background()); err == nil {
		t.Fatal("Healthy must fail once the directory is gone")
	}
	// A dead writer records a temporary failure.
	dead := &fileBackend{name: "dead", path: "-", w: errWriter{}, h: newHealth("dead")}
	if err := dead.Export(context.Background(), sampleBatch()); !IsTemporary(err) {
		t.Fatalf("dead writer err = %v", err)
	}
	if err := dead.Healthy(context.Background()); err == nil {
		t.Fatal("health must carry the last error")
	}
	if _, err := Open(Config{Backend: BackendFile, File: FileConfig{Path: filepath.Join(dir, "x", "y")}}); err != nil {
		t.Fatalf("file backend must create parent dirs: %v", err)
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk gone") }

func TestWebhookBackendAuthHeadersAndStatusClasses(t *testing.T) {
	var (
		mu       sync.Mutex
		gotHdr   http.Header
		gotBody  []byte
		status   = http.StatusAccepted
		requests int
	)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		gotHdr = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, srv.URL+"/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	b, err := Open(Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: srv.URL + "/audit", BearerToken: "tok", HMACKey: "k3y"}})
	if err != nil {
		t.Fatal(err)
	}
	batch := sampleBatch()
	if err := b.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if gotHdr.Get("Authorization") != "Bearer tok" || gotHdr.Get("Idempotency-Key") != batch.BatchID ||
		gotHdr.Get(HeaderBatchID) != batch.BatchID || gotHdr.Get(HeaderOffset) != "0" || gotHdr.Get(HeaderNodeID) != "node-a" ||
		gotHdr.Get("Content-Type") != ContentTypeNDJSON {
		t.Fatalf("headers = %v", gotHdr)
	}
	if !VerifySignature("k3y", gotBody, gotHdr.Get(HeaderSignature)) || VerifySignature("wrong", gotBody, gotHdr.Get(HeaderSignature)) {
		t.Fatal("HMAC signature did not verify")
	}
	if !bytes.Equal(gotBody, EncodeNDJSON(batch)) {
		t.Fatalf("body = %q", gotBody)
	}
	mu.Unlock()
	if err := b.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	status = http.StatusServiceUnavailable
	mu.Unlock()
	if err := b.Export(context.Background(), batch); !IsTemporary(err) {
		t.Fatalf("503 must be temporary: %v", err)
	}
	mu.Lock()
	status = http.StatusTooManyRequests
	mu.Unlock()
	if err := b.Export(context.Background(), batch); !IsTemporary(err) {
		t.Fatalf("429 must be temporary: %v", err)
	}
	mu.Lock()
	status = http.StatusForbidden
	mu.Unlock()
	if err := b.Export(context.Background(), batch); err == nil || IsTemporary(err) {
		t.Fatalf("403 must be a permanent failure: %v", err)
	}
	if err := b.Healthy(context.Background()); err == nil || !strings.Contains(err.Error(), "3 consecutive") {
		t.Fatalf("health after failures = %v", err)
	}
	mu.Lock()
	status = http.StatusOK
	mu.Unlock()
	if err := b.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := b.Healthy(context.Background()); err != nil {
		t.Fatalf("health must reset on success: %v", err)
	}

	// Redirects are refused: evidence must not bounce to a third host.
	rb, err := Open(Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: srv.URL + "/redirect"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rb.Export(context.Background(), batch); err == nil || IsTemporary(err) {
		t.Fatalf("redirect must be a permanent failure: %v", err)
	}
	mu.Lock()
	if requests != 6 {
		t.Fatalf("requests = %d (a followed redirect would add one)", requests)
	}
	mu.Unlock()

	// Unreachable receiver is temporary and honours the context.
	dead, err := Open(Config{Backend: BackendWebhook, Timeout: 200 * time.Millisecond, Webhook: WebhookConfig{URL: "http://127.0.0.1:1/audit"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := dead.Export(context.Background(), batch); !IsTemporary(err) {
		t.Fatalf("connection refused must be temporary: %v", err)
	}
}

// writeTestPKI mints a CA, a server cert for 127.0.0.1, and a client cert,
// so the mTLS path is exercised against a real TLS handshake.
func writeTestPKI(t *testing.T, dir string) (caFile, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	writePEM := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caKey := newKey()
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caFile = writePEM("ca.pem", "CERTIFICATE", caDER)

	leaf := func(serial int64, cn string, usage x509.ExtKeyUsage, ip net.IP) (string, string) {
		k := newKey()
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if ip != nil {
			tpl.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return writePEM(cn+".pem", "CERTIFICATE", der), writePEM(cn+".key", "EC PRIVATE KEY", keyDER)
	}
	serverCert, serverKey = leaf(2, "server", x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	clientCert, clientKey = leaf(3, "client", x509.ExtKeyUsageClientAuth, nil)
	return
}

func TestWebhookBackendMutualTLS(t *testing.T) {
	dir := t.TempDir()
	caFile, serverCert, serverKey, clientCert, clientKey := writeTestPKI(t, dir)
	caPEM, _ := os.ReadFile(caFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	srvCert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	var sawClientCN string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			sawClientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	b, err := Open(Config{Backend: BackendWebhook, Enterprise: true, Webhook: WebhookConfig{
		URL: srv.URL + "/audit", CAFile: caFile, CertFile: clientCert, KeyFile: clientKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Export(context.Background(), sampleBatch()); err != nil {
		t.Fatalf("mTLS export: %v", err)
	}
	if sawClientCN != "client" {
		t.Fatalf("server saw client CN %q", sawClientCN)
	}
	// Without the client certificate the receiver rejects the handshake.
	nb, err := Open(Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: srv.URL + "/audit", CAFile: caFile}})
	if err != nil {
		t.Fatal(err)
	}
	if err := nb.Export(context.Background(), sampleBatch()); !IsTemporary(err) {
		t.Fatalf("handshake failure must be temporary: %v", err)
	}
	// Bad material fails at Open, not on the first batch.
	if _, err := Open(Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: "https://x/y", CAFile: filepath.Join(dir, "missing.pem")}}); err == nil {
		t.Fatal("missing CA must fail Open")
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.pem"), []byte("nothing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: "https://x/y", CAFile: filepath.Join(dir, "empty.pem")}}); err == nil {
		t.Fatal("CA without certificates must fail Open")
	}
	if _, err := Open(Config{Backend: BackendWebhook, Webhook: WebhookConfig{URL: "https://x/y", CertFile: filepath.Join(dir, "missing.pem"), KeyFile: filepath.Join(dir, "missing.key")}}); err == nil {
		t.Fatal("missing client cert must fail Open")
	}
}

type fakeS3 struct {
	mu   sync.Mutex
	puts []*s3.PutObjectInput
	body [][]byte
	err  error
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	raw, _ := io.ReadAll(in.Body)
	f.puts = append(f.puts, in)
	f.body = append(f.body, raw)
	return &s3.PutObjectOutput{}, nil
}

func TestS3BackendKeyLayoutAndIdempotentResend(t *testing.T) {
	fake := &fakeS3{}
	b := newS3Backend(fake, S3Config{Bucket: "evidence", Prefix: "audit"})
	batch := sampleBatch()
	if err := b.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := b.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if len(fake.puts) != 2 {
		t.Fatalf("puts = %d", len(fake.puts))
	}
	wantKey := "audit/node=node-a/2026/09/11/node-a_0_abc.jsonl"
	for i, p := range fake.puts {
		if aws.ToString(p.Bucket) != "evidence" || aws.ToString(p.Key) != wantKey {
			t.Fatalf("put %d = %s/%s, want evidence/%s", i, aws.ToString(p.Bucket), aws.ToString(p.Key), wantKey)
		}
		if aws.ToString(p.ContentType) != ContentTypeNDJSON || aws.ToInt64(p.ContentLength) != int64(len(fake.body[i])) {
			t.Fatalf("put %d metadata = %+v", i, p)
		}
		if p.Metadata["aerol-batch-id"] != batch.BatchID || p.Metadata["aerol-node-id"] != "node-a" {
			t.Fatalf("put %d user metadata = %v", i, p.Metadata)
		}
		if !bytes.Equal(fake.body[i], EncodeNDJSON(batch)) {
			t.Fatalf("put %d body = %q", i, fake.body[i])
		}
	}
	if b.Name() != BackendS3 || b.Healthy(context.Background()) != nil {
		t.Fatal("name/health")
	}
	fake.err = errors.New("AccessDenied")
	if err := b.Export(context.Background(), batch); !IsTemporary(err) {
		t.Fatalf("s3 failure must be temporary: %v", err)
	}
	if err := b.Healthy(context.Background()); err == nil {
		t.Fatal("health must carry the failure")
	}
	// Key layout edge cases.
	if k := ObjectKey("", "", "", time.Time{}); !strings.HasPrefix(k, "node=unknown/") || !strings.HasSuffix(k, ".jsonl") {
		t.Fatalf("empty key = %q", k)
	}
	if k := ObjectKey("p", "n", "a/b:c", batch.ShippedAt); k != "p/node=n/2026/09/11/a_b_c.jsonl" {
		t.Fatalf("sanitized key = %q", k)
	}
}

// The real SDK client against an httptest S3-compatible endpoint proves the
// endpoint override, path-style addressing, and no aws-chunked framing.
func TestS3BackendRealClientAgainstCompatibleEndpoint(t *testing.T) {
	var (
		mu      sync.Mutex
		gotPath string
		gotBody []byte
		gotEnc  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		gotEnc = r.Header.Get("Content-Encoding")
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	client, err := newS3Client(context.Background(), S3Config{Endpoint: srv.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	b := newS3Backend(client, S3Config{Bucket: "bkt", Prefix: "audit"})
	batch := sampleBatch()
	if err := b.Export(context.Background(), batch); err != nil {
		t.Fatalf("real client export: %v", err)
	}
	mu.Lock()
	path, enc, body := gotPath, gotEnc, gotBody
	mu.Unlock()
	if path != "/bkt/audit/node=node-a/2026/09/11/node-a_0_abc.jsonl" {
		t.Fatalf("path = %q (path-style expected)", path)
	}
	if strings.Contains(enc, "aws-chunked") || !bytes.Equal(body, EncodeNDJSON(batch)) {
		t.Fatalf("body framing: enc=%q body=%q", enc, body)
	}
	// Static credentials path through Open works too (registry factory).
	t.Setenv("AWS_ENDPOINT_URL_S3", srv.URL)
	rb, err := Open(Config{Backend: BackendS3, S3: S3Config{Bucket: "bkt", Endpoint: srv.URL, Region: "us-east-1", PathStyle: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err := rb.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	_ = credentials.NewStaticCredentialsProvider
}

type fakeBus struct {
	topic, key string
	payload    []byte
	err        error
	closed     bool
}

func (f *fakeBus) Publish(_ context.Context, topic, key string, payload []byte) error {
	f.topic, f.key, f.payload = topic, key, payload
	return f.err
}
func (f *fakeBus) Close() error { f.closed = true; return nil }

func TestBusBackendSeam(t *testing.T) {
	RegisterBusPublisher(nil)
	if _, err := Open(Config{Backend: BackendBus, Bus: BusConfig{Topic: "audit"}}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("bus without publisher = %v", err)
	}
	fb := &fakeBus{}
	RegisterBusPublisher(func(cfg BusConfig) (BusPublisher, error) {
		if cfg.Topic != "audit" || cfg.Brokers != "k1:9092" {
			t.Fatalf("cfg = %+v", cfg)
		}
		return fb, nil
	})
	t.Cleanup(func() { RegisterBusPublisher(nil) })
	b, err := Open(Config{Backend: BackendBus, Bus: BusConfig{Topic: "audit", Brokers: "k1:9092"}})
	if err != nil {
		t.Fatal(err)
	}
	batch := sampleBatch()
	if err := b.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if fb.topic != "audit" || fb.key != batch.BatchID || !bytes.Equal(fb.payload, EncodeNDJSON(batch)) {
		t.Fatalf("published %s/%s %q", fb.topic, fb.key, fb.payload)
	}
	fb.err = errors.New("broker down")
	if err := b.Export(context.Background(), batch); !IsTemporary(err) {
		t.Fatalf("broker failure must be temporary: %v", err)
	}
	if err := b.Healthy(context.Background()); err == nil {
		t.Fatal("health")
	}
	if err := b.(interface{ Close() error }).Close(); err != nil || !fb.closed {
		t.Fatal("close")
	}
	RegisterBusPublisher(func(BusConfig) (BusPublisher, error) { return nil, errors.New("dial") })
	if _, err := Open(Config{Backend: BackendBus, Bus: BusConfig{Topic: "audit"}}); err == nil {
		t.Fatal("factory error must surface from Open")
	}
	if b.Name() != BackendBus {
		t.Fatal(b.Name())
	}
}

func TestTemporaryWrapping(t *testing.T) {
	if Temporary(nil) != nil {
		t.Fatal("nil stays nil")
	}
	if !IsTemporary(Temporary(errors.New("x"))) || IsTemporary(errors.New("x")) {
		t.Fatal("classification")
	}
}
