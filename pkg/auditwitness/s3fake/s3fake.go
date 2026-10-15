// Package s3fake is an in-memory S3 server for tests. It speaks just enough
// of the S3 REST API (path-style addressing, XML bodies, S3 error codes) for
// the real AWS SDK client to drive the audit witness and the offline verifier
// against it, with no production test hooks.
//
// Interface fakes were not enough (plans/open-audit-witness.md, D12): the
// witness's sharpest failure modes live on the wire. S3 refuses an upload to
// a bucket with default Object Lock retention unless it carries a checksum
// header, answers a GET for a missing key with 403 instead of 404 when the
// caller lacks s3:ListBucket (D19), lets a governance lock be bypassed only
// when the request carries the bypass header and the caller holds the
// permission (D7), and hides a delete-marked key from ListObjectsV2 but not
// from ListObjectVersions (C2). Each of those is modelled here, because each
// one changes what the witness must do.
//
// It is a test helper, not a general S3: one region, no auth checks beyond
// the permission switches on Policy, no multipart, no conditional requests.
package s3fake

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Lock modes, as S3 spells them.
const (
	ModeCompliance = "COMPLIANCE"
	ModeGovernance = "GOVERNANCE"
)

// Lock is a bucket's Object Lock configuration. A nil *Lock on BucketOptions
// means Object Lock is off. Mode empty means Object Lock is enabled with no
// default retention rule, which S3 allows and the witness must refuse.
type Lock struct {
	Mode  string
	Days  int
	Years int
}

// BucketOptions configures a bucket at creation.
type BucketOptions struct {
	Versioning bool
	Lock       *Lock
}

// Policy models the IAM permissions of the caller. The zero value is the
// node role the witness is designed for: list and read allowed, every delete
// denied by IAM, no governance bypass.
type Policy struct {
	// NoListBucket makes a GET of a missing key answer 403 AccessDenied, the
	// way S3 answers a caller without s3:ListBucket.
	NoListBucket bool
	// BypassGovernance grants s3:BypassGovernanceRetention.
	BypassGovernance bool
	// AllowDeleteMarker grants s3:DeleteObject: a DELETE without a version
	// id, which on a versioned bucket hides the key behind a delete marker.
	AllowDeleteMarker bool
	// AllowDeleteVersion grants s3:DeleteObjectVersion; the lock still has
	// the last word on a locked version.
	AllowDeleteVersion bool
}

// Version is one stored version of a key, as Versions reports it.
type Version struct {
	Key          string
	VersionID    string
	Body         []byte
	ETag         string
	LastModified time.Time
	DeleteMarker bool
	Mode         string
	RetainUntil  time.Time
}

type bucket struct {
	versioning string
	lock       *Lock
	// objects holds each key's versions, oldest first.
	objects map[string][]*Version
}

// Server is the fake. Embeds the httptest server, so URL and Close work.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	buckets  map[string]*bucket
	policy   Policy
	requests int
	ops      map[string]int
	seq      int
	// now is the server clock. LastModified is reported to the second, as
	// S3 does, so tests can build same-second ties by holding the clock.
	now func() time.Time
}

// New starts a fake with no buckets.
func New() *Server {
	s := &Server{buckets: map[string]*bucket{}, ops: map[string]int{}, now: time.Now}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// NewTLS starts a fake that serves https, for configurations that refuse a
// plain-http endpoint (enterprise mode). Point the SDK at CertificatePEM
// through AWS_CA_BUNDLE.
func NewTLS() *Server {
	s := &Server{buckets: map[string]*bucket{}, ops: map[string]int{}, now: time.Now}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// CertificatePEM is the TLS server's certificate, PEM encoded; nil for a
// plain-http fake.
func (s *Server) CertificatePEM() []byte {
	if s.TLS == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
}

// SetClock replaces the server clock; nil restores time.Now.
func (s *Server) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// SetPolicy replaces the caller's permissions.
func (s *Server) SetPolicy(p Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = p
}

// CreateBucket adds an empty bucket.
func (s *Server) CreateBucket(name string, opts BucketOptions) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &bucket{objects: map[string][]*Version{}, lock: opts.Lock}
	if opts.Versioning || opts.Lock != nil {
		// S3 turns versioning on with Object Lock and never lets it go.
		b.versioning = "Enabled"
	}
	s.buckets[name] = b
}

// Requests is the number of HTTP requests served so far.
func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// Ops counts requests by operation name (PutObject, GetObject, ...).
func (s *Server) Ops() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.ops))
	for k, v := range s.ops {
		out[k] = v
	}
	return out
}

// Versions returns a copy of a key's versions, oldest first.
func (s *Server) Versions(bucketName, key string) []Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[bucketName]
	if b == nil {
		return nil
	}
	out := make([]Version, 0, len(b.objects[key]))
	for _, v := range b.objects[key] {
		out = append(out, *v)
	}
	return out
}

// Put stores a version directly, bypassing checksum and permission checks:
// what another writer (a foreign node, an attacker with other credentials)
// leaves in the bucket.
func (s *Server) Put(bucketName, key string, body []byte) Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mustBucket(bucketName)
	return *s.putLocked(b, key, body)
}

// PutDeleteMarker hides a key the way a plain DELETE does on a versioned
// bucket: Object Lock protects versions, not the key's current pointer.
func (s *Server) PutDeleteMarker(bucketName, key string) Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mustBucket(bucketName)
	return *s.deleteMarkerLocked(b, key)
}

func (s *Server) mustBucket(name string) *bucket {
	b := s.buckets[name]
	if b == nil {
		panic(fmt.Sprintf("s3fake: no bucket %q", name))
	}
	return b
}

func (s *Server) newVersionID() string {
	s.seq++
	var r [6]byte
	_, _ = rand.Read(r[:])
	// A sequence prefix keeps IDs unique even when tests hold the clock.
	return fmt.Sprintf("v%06d-%s", s.seq, hex.EncodeToString(r[:]))
}

func (s *Server) putLocked(b *bucket, key string, body []byte) *Version {
	now := s.now().UTC()
	sum := md5.Sum(body)
	v := &Version{
		Key:          key,
		VersionID:    "null",
		Body:         append([]byte(nil), body...),
		ETag:         `"` + hex.EncodeToString(sum[:]) + `"`,
		LastModified: now,
	}
	if b.versioning == "Enabled" {
		v.VersionID = s.newVersionID()
	}
	if b.lock != nil && b.lock.Mode != "" {
		v.Mode = b.lock.Mode
		v.RetainUntil = now.AddDate(b.lock.Years, 0, b.lock.Days)
	}
	if b.versioning != "Enabled" {
		b.objects[key] = []*Version{v}
		return v
	}
	b.objects[key] = append(b.objects[key], v)
	return v
}

func (s *Server) deleteMarkerLocked(b *bucket, key string) *Version {
	v := &Version{Key: key, VersionID: s.newVersionID(), LastModified: s.now().UTC(), DeleteMarker: true}
	b.objects[key] = append(b.objects[key], v)
	return v
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	bucketName, key := splitPath(r.URL.Path)
	q := r.URL.Query()
	op := operation(r.Method, key, q)
	s.ops[op]++
	b := s.buckets[bucketName]
	if b == nil {
		writeError(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}
	switch op {
	case "PutObject":
		s.putObject(w, r, b, key)
	case "GetObject":
		s.getObject(w, b, key, q.Get("versionId"))
	case "DeleteObject":
		s.deleteObject(w, r, b, key, q.Get("versionId"))
	case "ListObjectVersions":
		s.listObjectVersions(w, bucketName, b, q)
	case "ListObjectsV2":
		s.listObjectsV2(w, bucketName, b, q)
	case "GetBucketVersioning":
		writeXML(w, versioningConfiguration{Status: b.versioning})
	case "GetObjectLockConfiguration":
		s.getObjectLockConfiguration(w, b)
	default:
		writeError(w, http.StatusNotImplemented, "NotImplemented", "s3fake does not implement "+op)
	}
}

func splitPath(p string) (bucketName, key string) {
	p = strings.TrimPrefix(p, "/")
	bucketName, key, _ = strings.Cut(p, "/")
	return bucketName, key
}

func operation(method, key string, q url.Values) string {
	switch method {
	case http.MethodPut:
		if key != "" {
			return "PutObject"
		}
	case http.MethodGet:
		switch {
		case key != "":
			return "GetObject"
		case q.Get("list-type") == "2":
			return "ListObjectsV2"
		case q.Has("versions"):
			return "ListObjectVersions"
		case q.Has("versioning"):
			return "GetBucketVersioning"
		case q.Has("object-lock"):
			return "GetObjectLockConfiguration"
		}
	case http.MethodDelete:
		if key != "" {
			return "DeleteObject"
		}
	}
	return method + " " + q.Encode()
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, b *bucket, key string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}
	header := r.Header
	if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
		// Over TLS the SDK sends a checksummed upload as aws-chunked with the
		// checksum in a trailer; over plain http it puts it in a header. Real
		// S3 accepts both, so the fake must too, or the https path that
		// production uses would go untested.
		data, trailers, err := decodeAWSChunked(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "IncompleteBody", err.Error())
			return
		}
		if want := r.Header.Get("x-amz-decoded-content-length"); want != strconv.Itoa(len(data)) {
			writeError(w, http.StatusBadRequest, "IncompleteBody", "decoded length "+strconv.Itoa(len(data))+" does not match x-amz-decoded-content-length "+want)
			return
		}
		body = data
		header = r.Header.Clone()
		for k, v := range trailers {
			header[k] = v
		}
	}
	if b.lock != nil && b.lock.Mode != "" {
		// S3: "Content-MD5 OR x-amz-checksum- HTTP header is required for Put
		// Object requests with Object Lock parameters". A default retention
		// rule counts as Object Lock parameters on every upload.
		if msg := checksumProblem(header, body); msg != "" {
			writeError(w, http.StatusBadRequest, "InvalidRequest", msg)
			return
		}
	}
	v := s.putLocked(b, key, body)
	w.Header().Set("ETag", v.ETag)
	if v.VersionID != "null" {
		w.Header().Set("x-amz-version-id", v.VersionID)
	}
	w.WriteHeader(http.StatusOK)
}

// decodeAWSChunked unframes an aws-chunked body: hex-sized chunks (each
// size line may carry a ";chunk-signature=" extension), a zero-size chunk,
// then trailer lines ending in a blank line.
func decodeAWSChunked(raw []byte) ([]byte, http.Header, error) {
	var data []byte
	trailers := http.Header{}
	rest := raw
	next := func() (string, error) {
		i := bytes.Index(rest, []byte("\r\n"))
		if i < 0 {
			return "", fmt.Errorf("aws-chunked body is truncated")
		}
		line := string(rest[:i])
		rest = rest[i+2:]
		return line, nil
	}
	for {
		line, err := next()
		if err != nil {
			return nil, nil, err
		}
		sizeText, _, _ := strings.Cut(line, ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil || size < 0 {
			return nil, nil, fmt.Errorf("aws-chunked size %q is not hex", sizeText)
		}
		if size == 0 {
			break
		}
		if int64(len(rest)) < size+2 || string(rest[size:size+2]) != "\r\n" {
			return nil, nil, fmt.Errorf("aws-chunked chunk of %d bytes is truncated", size)
		}
		data = append(data, rest[:size]...)
		rest = rest[size+2:]
	}
	for {
		line, err := next()
		if err != nil {
			return nil, nil, err
		}
		if line == "" {
			return data, trailers, nil
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return nil, nil, fmt.Errorf("aws-chunked trailer %q has no value", line)
		}
		trailers.Set(strings.TrimSpace(k), strings.TrimSpace(v))
	}
}

// checksumProblem reports why an upload's integrity headers would not satisfy
// S3 on an Object Lock bucket, or "" when they would.
func checksumProblem(h http.Header, body []byte) string {
	if md := h.Get("Content-MD5"); md != "" {
		sum := md5.Sum(body)
		if md != base64.StdEncoding.EncodeToString(sum[:]) {
			return "The Content-MD5 you specified did not match what we received."
		}
		return ""
	}
	algo := strings.ToUpper(h.Get("x-amz-sdk-checksum-algorithm"))
	got := h.Get("x-amz-checksum-sha256")
	if algo == "" || got == "" {
		return "Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with Object Lock parameters"
	}
	if algo != "SHA256" {
		return "s3fake only verifies SHA256 checksums, got " + algo
	}
	sum := sha256.Sum256(body)
	if got != base64.StdEncoding.EncodeToString(sum[:]) {
		return "The SHA256 you specified did not match the calculated checksum."
	}
	return ""
}

func (s *Server) getObject(w http.ResponseWriter, b *bucket, key, versionID string) {
	versions := b.objects[key]
	if versionID != "" {
		for _, v := range versions {
			if v.VersionID != versionID {
				continue
			}
			if v.DeleteMarker {
				w.Header().Set("x-amz-delete-marker", "true")
				writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "The specified method is not allowed against this resource.")
				return
			}
			writeObject(w, v)
			return
		}
		writeError(w, http.StatusNotFound, "NoSuchVersion", "The specified version does not exist.")
		return
	}
	if len(versions) == 0 {
		if s.policy.NoListBucket {
			writeError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		writeError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	current := versions[len(versions)-1]
	if current.DeleteMarker {
		w.Header().Set("x-amz-delete-marker", "true")
		w.Header().Set("x-amz-version-id", current.VersionID)
		writeError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	writeObject(w, current)
}

func writeObject(w http.ResponseWriter, v *Version) {
	w.Header().Set("ETag", v.ETag)
	w.Header().Set("Last-Modified", v.LastModified.Format(http.TimeFormat))
	w.Header().Set("Content-Length", strconv.Itoa(len(v.Body)))
	if v.VersionID != "null" {
		w.Header().Set("x-amz-version-id", v.VersionID)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(v.Body)
}

func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request, b *bucket, key, versionID string) {
	if (versionID == "" && !s.policy.AllowDeleteMarker) || (versionID != "" && !s.policy.AllowDeleteVersion) {
		writeError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}
	if versionID == "" {
		if b.versioning != "Enabled" {
			delete(b.objects, key)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		v := s.deleteMarkerLocked(b, key)
		w.Header().Set("x-amz-delete-marker", "true")
		w.Header().Set("x-amz-version-id", v.VersionID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	versions := b.objects[key]
	for i, v := range versions {
		if v.VersionID != versionID {
			continue
		}
		if !v.DeleteMarker && v.RetainUntil.After(s.now()) {
			bypass := strings.EqualFold(r.Header.Get("x-amz-bypass-governance-retention"), "true")
			if v.Mode == ModeCompliance || !(bypass && s.policy.BypassGovernance) {
				writeError(w, http.StatusForbidden, "AccessDenied", "Access Denied because object protected by object lock.")
				return
			}
		}
		b.objects[key] = append(versions[:i:i], versions[i+1:]...)
		if len(b.objects[key]) == 0 {
			delete(b.objects, key)
		}
		w.Header().Set("x-amz-version-id", versionID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// S3 answers a delete of an absent version with success.
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getObjectLockConfiguration(w http.ResponseWriter, b *bucket) {
	if b.lock == nil {
		writeError(w, http.StatusNotFound, "ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket")
		return
	}
	cfg := objectLockConfiguration{ObjectLockEnabled: "Enabled"}
	if b.lock.Mode != "" {
		ret := &defaultRetention{Mode: b.lock.Mode}
		if b.lock.Years > 0 {
			ret.Years = b.lock.Years
		} else {
			ret.Days = b.lock.Days
		}
		cfg.Rule = &lockRule{DefaultRetention: ret}
	}
	writeXML(w, cfg)
}

// listObjectVersions walks keys in order and, within a key, versions newest
// first: the order S3 returns, which the verifier relies on for ties inside
// one key (LastModified is only reported to the second).
func (s *Server) listObjectVersions(w http.ResponseWriter, bucketName string, b *bucket, q url.Values) {
	maxKeys := 1000
	if mk, err := strconv.Atoi(q.Get("max-keys")); err == nil && mk > 0 && mk < maxKeys {
		maxKeys = mk
	}
	res := listVersionsResult{
		Name: bucketName, Prefix: q.Get("prefix"), Delimiter: q.Get("delimiter"),
		KeyMarker: q.Get("key-marker"), VersionIDMarker: q.Get("version-id-marker"), MaxKeys: maxKeys,
	}
	s.fillVersionPage(b, &res)
	writeXML(w, res)
}

// fillVersionPage adds entries until the page holds MaxKeys, then marks it
// truncated only if another entry exists.
func (s *Server) fillVersionPage(b *bucket, res *listVersionsResult) {
	prefix, delimiter, keyMarker, versionMarker := res.Prefix, res.Delimiter, res.KeyMarker, res.VersionIDMarker
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	count := 0
	seenPrefix := map[string]bool{}
	for _, k := range keys {
		if delimiter != "" {
			if i := strings.Index(k[len(prefix):], delimiter); i >= 0 {
				cp := k[:len(prefix)+i+len(delimiter)]
				// A rolled-up prefix is resumed past, never re-entered.
				if (keyMarker != "" && cp <= keyMarker) || seenPrefix[cp] {
					continue
				}
				if count >= res.MaxKeys {
					res.IsTruncated = true
					return
				}
				seenPrefix[cp] = true
				res.CommonPrefixes = append(res.CommonPrefixes, commonPrefix{Prefix: cp})
				res.NextKeyMarker, res.NextVersionIDMarker = cp, ""
				count++
				continue
			}
		}
		if keyMarker != "" && k < keyMarker {
			continue
		}
		versions := b.objects[k]
		skipping := keyMarker != "" && k == keyMarker
		if skipping && versionMarker == "" {
			// A key marker alone means "keys after this one".
			continue
		}
		for i := len(versions) - 1; i >= 0; i-- {
			v := versions[i]
			if skipping {
				if v.VersionID == versionMarker {
					skipping = false
				}
				continue
			}
			if count >= res.MaxKeys {
				res.IsTruncated = true
				return
			}
			entry := versionEntry{
				Key: k, VersionID: v.VersionID, IsLatest: i == len(versions)-1,
				LastModified: s3Time(v.LastModified),
			}
			if v.DeleteMarker {
				res.Entries = append(res.Entries, xmlEntry{DeleteMarker: &entry})
			} else {
				entry.ETag = v.ETag
				entry.Size = int64(len(v.Body))
				entry.StorageClass = "STANDARD"
				res.Entries = append(res.Entries, xmlEntry{Version: &entry})
			}
			res.NextKeyMarker, res.NextVersionIDMarker = k, v.VersionID
			count++
		}
	}
	// A complete listing carries no continuation markers.
	res.NextKeyMarker, res.NextVersionIDMarker = "", ""
}

// listObjectsV2 lists current versions only: a key whose newest version is
// a delete marker is left out, which is exactly why the witness must not use
// it to find a node's newest day (C2). The continuation token is the last
// key returned.
func (s *Server) listObjectsV2(w http.ResponseWriter, bucketName string, b *bucket, q url.Values) {
	prefix, after := q.Get("prefix"), q.Get("continuation-token")
	maxKeys := 1000
	if mk, err := strconv.Atoi(q.Get("max-keys")); err == nil && mk > 0 && mk < maxKeys {
		maxKeys = mk
	}
	keys := make([]string, 0, len(b.objects))
	for k, versions := range b.objects {
		if strings.HasPrefix(k, prefix) && k > after && !versions[len(versions)-1].DeleteMarker {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	res := listBucketResult{Name: bucketName, Prefix: prefix, MaxKeys: maxKeys, ContinuationToken: after}
	for i, k := range keys {
		if i == maxKeys {
			res.IsTruncated = true
			res.NextContinuationToken = keys[i-1]
			break
		}
		v := b.objects[k][len(b.objects[k])-1]
		res.Contents = append(res.Contents, objectEntry{Key: k, LastModified: s3Time(v.LastModified), ETag: v.ETag, Size: int64(len(v.Body)), StorageClass: "STANDARD"})
	}
	res.KeyCount = len(res.Contents)
	writeXML(w, res)
}

type listBucketResult struct {
	XMLName               xml.Name      `xml:"ListBucketResult"`
	Name                  string        `xml:"Name"`
	Prefix                string        `xml:"Prefix"`
	MaxKeys               int           `xml:"MaxKeys"`
	KeyCount              int           `xml:"KeyCount"`
	IsTruncated           bool          `xml:"IsTruncated"`
	ContinuationToken     string        `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
	Contents              []objectEntry `xml:"Contents"`
}

type objectEntry struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// s3Time formats a timestamp the way S3 list results do: milliseconds are
// always zero, so two writes in one second compare equal.
func s3Time(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05.000Z")
}

type versioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	Status  string   `xml:"Status,omitempty"`
}

type objectLockConfiguration struct {
	XMLName           xml.Name  `xml:"ObjectLockConfiguration"`
	ObjectLockEnabled string    `xml:"ObjectLockEnabled"`
	Rule              *lockRule `xml:"Rule,omitempty"`
}

type lockRule struct {
	DefaultRetention *defaultRetention `xml:"DefaultRetention"`
}

type defaultRetention struct {
	Mode  string `xml:"Mode"`
	Days  int    `xml:"Days,omitempty"`
	Years int    `xml:"Years,omitempty"`
}

type listVersionsResult struct {
	XMLName             xml.Name       `xml:"ListVersionsResult"`
	Name                string         `xml:"Name"`
	Prefix              string         `xml:"Prefix"`
	KeyMarker           string         `xml:"KeyMarker"`
	VersionIDMarker     string         `xml:"VersionIdMarker"`
	NextKeyMarker       string         `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string         `xml:"NextVersionIdMarker,omitempty"`
	MaxKeys             int            `xml:"MaxKeys"`
	Delimiter           string         `xml:"Delimiter,omitempty"`
	IsTruncated         bool           `xml:"IsTruncated"`
	Entries             []xmlEntry     `xml:",any"`
	CommonPrefixes      []commonPrefix `xml:"CommonPrefixes"`
}

// xmlEntry keeps versions and delete markers interleaved in document order,
// as S3 sends them.
type xmlEntry struct {
	Version      *versionEntry
	DeleteMarker *versionEntry
}

func (e xmlEntry) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	if e.DeleteMarker != nil {
		return enc.EncodeElement(e.DeleteMarker, xml.StartElement{Name: xml.Name{Local: "DeleteMarker"}})
	}
	return enc.EncodeElement(e.Version, xml.StartElement{Name: xml.Name{Local: "Version"}})
}

type versionEntry struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag,omitempty"`
	Size         int64  `xml:"Size,omitempty"`
	StorageClass string `xml:"StorageClass,omitempty"`
}

type commonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type errorBody struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	_ = xml.NewEncoder(&buf).Encode(errorBody{Code: code, Message: msg})
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeXML(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	if err := xml.NewEncoder(&buf).Encode(v); err != nil {
		writeError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
