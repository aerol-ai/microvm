package s3fake

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/aerol-ai/microvm/pkg/auditexport"
)

func client(t *testing.T, s *Server) *s3.Client {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	c, err := auditexport.NewS3Client(context.Background(), auditexport.S3Config{Endpoint: s.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func code(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

func put(t *testing.T, c *s3.Client, bucket, key, body string) *s3.PutObjectOutput {
	t.Helper()
	out, err := c.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader(body),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	})
	if err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
	return out
}

func get(c *s3.Client, bucket, key, version string) (string, error) {
	in := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if version != "" {
		in.VersionId = aws.String(version)
	}
	out, err := c.GetObject(context.Background(), in)
	if err != nil {
		return "", err
	}
	defer out.Body.Close()
	b, err := io.ReadAll(out.Body)
	return string(b), err
}

func TestVersionedBucketLifecycle(t *testing.T) {
	s := New()
	defer s.Close()
	clock := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return clock })
	s.CreateBucket("b", BucketOptions{Versioning: true})
	s.SetPolicy(Policy{AllowDeleteMarker: true, AllowDeleteVersion: true})
	c := client(t, s)

	v1 := put(t, c, "b", "k", "one")
	v2 := put(t, c, "b", "k", "two")
	if aws.ToString(v1.VersionId) == aws.ToString(v2.VersionId) || aws.ToString(v1.VersionId) == "" {
		t.Fatalf("version ids %q %q", aws.ToString(v1.VersionId), aws.ToString(v2.VersionId))
	}
	if body, err := get(c, "b", "k", ""); err != nil || body != "two" {
		t.Fatalf("current = %q %v", body, err)
	}
	if body, err := get(c, "b", "k", aws.ToString(v1.VersionId)); err != nil || body != "one" {
		t.Fatalf("v1 = %q %v", body, err)
	}
	if _, err := get(c, "b", "k", "nope"); code(err) != "NoSuchVersion" {
		t.Fatalf("missing version err = %v", err)
	}
	// A plain delete hides the key behind a marker; versions survive.
	del, err := c.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("k")})
	if err != nil || !aws.ToBool(del.DeleteMarker) {
		t.Fatalf("delete = %+v %v", del, err)
	}
	if _, err := get(c, "b", "k", ""); code(err) != "NoSuchKey" {
		t.Fatalf("hidden key err = %v", err)
	}
	if _, err := get(c, "b", "k", aws.ToString(del.VersionId)); err == nil {
		t.Fatal("GET of a delete marker version must fail")
	}
	if n := len(s.Versions("b", "k")); n != 3 {
		t.Fatalf("versions = %d", n)
	}
	// Deleting versions one by one removes the key.
	for _, v := range s.Versions("b", "k") {
		if _, err := c.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("k"), VersionId: aws.String(v.VersionID)}); err != nil {
			t.Fatal(err)
		}
	}
	if s.Versions("b", "k") != nil && len(s.Versions("b", "k")) != 0 {
		t.Fatal("key must be gone")
	}
	// Deleting an absent version succeeds, as on S3.
	if _, err := c.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("k"), VersionId: aws.String("gone")}); err != nil {
		t.Fatal(err)
	}
	if s.Versions("missing", "k") != nil {
		t.Fatal("versions of a missing bucket must be nil")
	}
	if s.Requests() == 0 || s.Ops()["PutObject"] != 2 {
		t.Fatalf("ops = %v", s.Ops())
	}
}

func TestUnversionedBucket(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{})
	s.SetPolicy(Policy{AllowDeleteMarker: true})
	c := client(t, s)
	out := put(t, c, "b", "k", "one")
	if out.VersionId != nil {
		t.Fatalf("unversioned put returned version %q", aws.ToString(out.VersionId))
	}
	put(t, c, "b", "k", "two")
	if v := s.Versions("b", "k"); len(v) != 1 || string(v[0].Body) != "two" {
		t.Fatalf("versions = %+v", v)
	}
	if _, err := c.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("k")}); err != nil {
		t.Fatal(err)
	}
	if _, err := get(c, "b", "k", ""); code(err) != "NoSuchKey" {
		t.Fatalf("err = %v", err)
	}
	v, err := c.GetBucketVersioning(context.Background(), &s3.GetBucketVersioningInput{Bucket: aws.String("b")})
	if err != nil || v.Status != "" {
		t.Fatalf("versioning = %+v %v", v, err)
	}
	if _, err := c.GetObjectLockConfiguration(context.Background(), &s3.GetObjectLockConfigurationInput{Bucket: aws.String("b")}); code(err) != "ObjectLockConfigurationNotFoundError" {
		t.Fatalf("lock err = %v", err)
	}
}

func TestObjectLockRules(t *testing.T) {
	clock := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		lock     Lock
		policy   Policy
		bypass   bool
		advance  time.Duration
		wantCode string
	}{
		{"compliance refuses even with bypass", Lock{Mode: ModeCompliance, Days: 1}, Policy{AllowDeleteVersion: true, BypassGovernance: true}, true, 0, "AccessDenied"},
		{"governance refuses without the header", Lock{Mode: ModeGovernance, Days: 1}, Policy{AllowDeleteVersion: true, BypassGovernance: true}, false, 0, "AccessDenied"},
		{"governance refuses without the permission", Lock{Mode: ModeGovernance, Days: 1}, Policy{AllowDeleteVersion: true}, true, 0, "AccessDenied"},
		{"governance bypass with both", Lock{Mode: ModeGovernance, Days: 1}, Policy{AllowDeleteVersion: true, BypassGovernance: true}, true, 0, ""},
		{"expired lock", Lock{Mode: ModeCompliance, Days: 1}, Policy{AllowDeleteVersion: true}, false, 49 * time.Hour, ""},
		{"years rule", Lock{Mode: ModeCompliance, Years: 1}, Policy{AllowDeleteVersion: true}, false, 300 * 24 * time.Hour, "AccessDenied"},
		{"IAM denies the version delete", Lock{Mode: ModeGovernance, Days: 1}, Policy{BypassGovernance: true}, true, 0, "AccessDenied"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := clock
			s := New()
			defer s.Close()
			s.SetClock(func() time.Time { return now })
			lock := c.lock
			s.CreateBucket("b", BucketOptions{Lock: &lock})
			s.SetPolicy(c.policy)
			cl := client(t, s)
			out := put(t, cl, "b", "k", "x")
			now = now.Add(c.advance)
			_, err := cl.DeleteObject(context.Background(), &s3.DeleteObjectInput{
				Bucket: aws.String("b"), Key: aws.String("k"), VersionId: out.VersionId,
				BypassGovernanceRetention: aws.Bool(c.bypass),
			})
			if got := code(err); got != c.wantCode {
				t.Fatalf("delete code = %q (%v), want %q", got, err, c.wantCode)
			}
		})
	}
}

func TestLockConfigurationXML(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("days", BucketOptions{Lock: &Lock{Mode: ModeGovernance, Days: 3}})
	s.CreateBucket("years", BucketOptions{Lock: &Lock{Mode: ModeCompliance, Years: 2}})
	s.CreateBucket("norule", BucketOptions{Lock: &Lock{}})
	c := client(t, s)
	get := func(b string) *types.ObjectLockConfiguration {
		out, err := c.GetObjectLockConfiguration(context.Background(), &s3.GetObjectLockConfigurationInput{Bucket: aws.String(b)})
		if err != nil {
			t.Fatal(err)
		}
		return out.ObjectLockConfiguration
	}
	if r := get("days").Rule.DefaultRetention; r.Mode != types.ObjectLockRetentionModeGovernance || aws.ToInt32(r.Days) != 3 {
		t.Fatalf("days rule = %+v", r)
	}
	if r := get("years").Rule.DefaultRetention; aws.ToInt32(r.Years) != 2 || r.Days != nil {
		t.Fatalf("years rule = %+v", r)
	}
	if cfg := get("norule"); cfg.ObjectLockEnabled != types.ObjectLockEnabledEnabled || cfg.Rule != nil {
		t.Fatalf("no-rule cfg = %+v", cfg)
	}
	v, err := c.GetBucketVersioning(context.Background(), &s3.GetBucketVersioningInput{Bucket: aws.String("days")})
	if err != nil || v.Status != types.BucketVersioningStatusEnabled {
		t.Fatalf("Object Lock must imply versioning: %+v %v", v, err)
	}
}

func TestChecksumRules(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{Lock: &Lock{Mode: ModeCompliance, Days: 1}})
	c := client(t, s)
	if _, err := c.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("k"), Body: strings.NewReader("x")}); code(err) != "InvalidRequest" {
		t.Fatalf("no checksum err = %v", err)
	}
	sum := md5.Sum([]byte("x"))
	good := base64.StdEncoding.EncodeToString(sum[:])
	raw := func(h map[string]string, enc string) int {
		req, _ := http.NewRequest(http.MethodPut, s.URL+"/b/k", bytes.NewReader([]byte("x")))
		for k, v := range h {
			req.Header.Set(k, v)
		}
		if enc != "" {
			req.Header.Set("Content-Encoding", enc)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	cases := []struct {
		name string
		h    map[string]string
		enc  string
		want int
	}{
		{"content-md5", map[string]string{"Content-MD5": good}, "", http.StatusOK},
		{"bad content-md5", map[string]string{"Content-MD5": "AAAA"}, "", http.StatusBadRequest},
		{"wrong sha256", map[string]string{"x-amz-sdk-checksum-algorithm": "SHA256", "x-amz-checksum-sha256": "AAAA"}, "", http.StatusBadRequest},
		{"other algorithm", map[string]string{"x-amz-sdk-checksum-algorithm": "CRC32", "x-amz-checksum-sha256": "AAAA"}, "", http.StatusBadRequest},
		{"aws-chunked body that is not chunked", map[string]string{"Content-MD5": good}, "aws-chunked", http.StatusBadRequest},
	}
	for _, cs := range cases {
		if got := raw(cs.h, cs.enc); got != cs.want {
			t.Errorf("%s: status %d, want %d", cs.name, got, cs.want)
		}
	}
}

func TestPermissionsAndRouting(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{Versioning: true})
	s.SetPolicy(Policy{NoListBucket: true})
	c := client(t, s)
	if _, err := get(c, "b", "missing", ""); code(err) != "AccessDenied" {
		t.Fatalf("missing key without ListBucket err = %v", err)
	}
	s.SetPolicy(Policy{})
	if _, err := c.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String("b"), Key: aws.String("k")}); code(err) != "AccessDenied" {
		t.Fatalf("denied delete err = %v", err)
	}
	if _, err := get(c, "nobucket", "k", ""); code(err) != "NoSuchBucket" {
		t.Fatalf("missing bucket err = %v", err)
	}
	if _, err := c.HeadBucket(context.Background(), &s3.HeadBucketInput{Bucket: aws.String("b")}); err == nil {
		t.Fatal("unimplemented operations must fail")
	}
	s.SetClock(nil)
	// Direct helpers record foreign writes and markers.
	v := s.Put("b", "k", []byte("raw"))
	m := s.PutDeleteMarker("b", "k")
	if v.VersionID == m.VersionID || !m.DeleteMarker {
		t.Fatalf("put %+v marker %+v", v, m)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a helper on a missing bucket must panic")
		}
	}()
	s.Put("nobucket", "k", nil)
}

func TestListObjectVersions(t *testing.T) {
	s := New()
	defer s.Close()
	clock := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return clock })
	s.CreateBucket("b", BucketOptions{Versioning: true})
	c := client(t, s)
	for _, k := range []string{"p/node=a/day=2026-10-09/head.json", "p/node=a/day=2026-10-10/head.json", "p/node=b/day=2026-10-10/head.json"} {
		put(t, c, "b", k, "1")
		put(t, c, "b", k, "2")
	}
	s.PutDeleteMarker("b", "p/node=a/day=2026-10-10/head.json")

	// Delimited listing rolls days up into common prefixes, page by page.
	var prefixes []string
	in := &s3.ListObjectVersionsInput{Bucket: aws.String("b"), Prefix: aws.String("p/node=a/"), Delimiter: aws.String("/"), MaxKeys: aws.Int32(1)}
	for page := 0; ; page++ {
		out, err := c.ListObjectVersions(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		for _, cp := range out.CommonPrefixes {
			prefixes = append(prefixes, aws.ToString(cp.Prefix))
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		if page > 5 {
			t.Fatal("pagination does not end")
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	if strings.Join(prefixes, ",") != "p/node=a/day=2026-10-09/,p/node=a/day=2026-10-10/" {
		t.Fatalf("prefixes = %v", prefixes)
	}

	// An undelimited listing returns every version newest first per key,
	// delete markers included, resumable mid-key.
	var seen []string
	var markers int
	in = &s3.ListObjectVersionsInput{Bucket: aws.String("b"), Prefix: aws.String("p/"), MaxKeys: aws.Int32(2)}
	for {
		out, err := c.ListObjectVersions(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range out.Versions {
			seen = append(seen, aws.ToString(v.Key)+"@"+aws.ToString(v.VersionId))
			if !aws.ToTime(v.LastModified).Equal(clock) {
				t.Fatalf("LastModified = %v", v.LastModified)
			}
		}
		for _, m := range out.DeleteMarkers {
			if !aws.ToBool(m.IsLatest) {
				t.Fatal("the marker is the newest entry")
			}
			markers++
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = out.NextKeyMarker, out.NextVersionIdMarker
	}
	if len(seen) != 6 || markers != 1 {
		t.Fatalf("seen %d versions %v and %d markers", len(seen), seen, markers)
	}
	for i := 0; i+1 < len(seen); i += 2 {
		k1, v1, _ := strings.Cut(seen[i], "@")
		k2, v2, _ := strings.Cut(seen[i+1], "@")
		if k1 != k2 || v1 <= v2 {
			t.Fatalf("within a key versions must be newest first: %v", seen)
		}
	}

	// A key marker alone resumes after that key.
	out, err := c.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: aws.String("b"), Prefix: aws.String("p/"), KeyMarker: aws.String("p/node=a/day=2026-10-10/head.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Versions) != 2 || aws.ToString(out.Versions[0].Key) != "p/node=b/day=2026-10-10/head.json" {
		t.Fatalf("after-key listing = %+v", out.Versions)
	}
}

// Over TLS the SDK frames a checksummed upload as aws-chunked with the
// checksum in a trailer; the fake must accept that and still refuse an
// upload with no checksum at all.
func TestTLSUploadsUseTrailingChecksums(t *testing.T) {
	s := NewTLS()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{Lock: &Lock{Mode: ModeCompliance, Days: 1}})
	ca := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(ca, s.CertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", ca)
	c := client(t, s)
	put(t, c, "b", "k", "payload")
	if v := s.Versions("b", "k"); len(v) != 1 || string(v[0].Body) != "payload" {
		t.Fatalf("stored %+v", v)
	}
	if _, err := c.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("b"), Key: aws.String("k"), Body: strings.NewReader("x")}); code(err) != "InvalidRequest" {
		t.Fatalf("no checksum over TLS err = %v", err)
	}
	if New().CertificatePEM() != nil {
		t.Fatal("a plain-http fake has no certificate")
	}
}

func TestDecodeAWSChunked(t *testing.T) {
	cases := []struct {
		name, raw, data, err string
	}{
		{"two chunks and a trailer", "3;chunk-signature=x\r\nabc\r\n2\r\nde\r\n0\r\nx-amz-checksum-sha256:AAAA\r\n\r\n", "abcde", ""},
		{"no trailer", "1\r\na\r\n0\r\n\r\n", "a", ""},
		{"truncated size line", "3", "", "truncated"},
		{"size not hex", "zz\r\n", "", "not hex"},
		{"chunk shorter than its size", "5\r\nab\r\n", "", "truncated"},
		{"trailer without a colon", "0\r\nnovalue\r\n\r\n", "", "has no value"},
		{"missing final blank line", "0\r\nx-amz-checksum-sha256:AAAA\r\n", "", "truncated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, trailers, err := decodeAWSChunked([]byte(c.raw))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || string(data) != c.data {
				t.Fatalf("data = %q, %v", data, err)
			}
			if c.name == "two chunks and a trailer" && trailers.Get("x-amz-checksum-sha256") != "AAAA" {
				t.Fatalf("trailers = %v", trailers)
			}
		})
	}
}

func TestChunkedLengthMismatch(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{Versioning: true})
	req, _ := http.NewRequest(http.MethodPut, s.URL+"/b/k", strings.NewReader("1\r\na\r\n0\r\n\r\n"))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-decoded-content-length", "5")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// ListObjectsV2 shows current versions only, so a delete-marked key is
// invisible to it: the fake must reproduce that, since the witness avoids
// it for exactly this reason.
func TestListObjectsV2(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{Versioning: true})
	c := client(t, s)
	for _, k := range []string{"p/a", "p/b", "p/c", "q/d"} {
		put(t, c, "b", k, "x")
	}
	s.PutDeleteMarker("b", "p/b")
	var keys []string
	in := &s3.ListObjectsV2Input{Bucket: aws.String("b"), Prefix: aws.String("p/"), MaxKeys: aws.Int32(1)}
	for page := 0; ; page++ {
		out, err := c.ListObjectsV2(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range out.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		if page > 5 {
			t.Fatal("pagination does not end")
		}
		in.ContinuationToken = out.NextContinuationToken
	}
	if strings.Join(keys, ",") != "p/a,p/c" {
		t.Fatalf("keys = %v", keys)
	}
}
