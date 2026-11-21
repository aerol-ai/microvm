// Package multipartspool parses a multipart/form-data request body the way
// (*http.Request).ParseMultipartForm does, except for where a file part too
// big for memory goes.
//
// The standard library writes such a part with os.CreateTemp("", …), into
// os.TempDir(): the host's shared temp folder, which every other process on
// the host shares, and where the file stays if nothing calls RemoveAll.
// sandboxd parses tenant uploads as root, so that put tenant bytes in
// root-owned files in a folder it does not own. Here the part goes into a
// private (0700) folder made for that one request, under a spool folder the
// daemon owns, and Form.RemoveAll removes the whole folder.
//
// Uploads are spooled, not streamed, because the facades accept the parts in
// any order (a `path` field may follow its `file` part), and every check runs
// before anything is sent on: a refused form uploads nothing.
package multipartspool

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// dirPerm keeps the spool and every request folder to the daemon's user.
	dirPerm = 0o700

	// The limits mime/multipart's ReadForm applies by default, so a form
	// this package accepts is one ParseMultipartForm would have accepted.
	maxParts         = 1000     // GODEBUG multipartmaxparts
	maxHeaderValues  = 10000    // GODEBUG multipartmaxheaders
	valueMemoryExtra = 10 << 20 // ReadForm's reserve for non-file parts
	mapEntryOverhead = 200
	fileHeaderSize   = 100

	// requestDirPrefix names every request folder, so a sweep only ever
	// touches folders this package made.
	requestDirPrefix = "req-"
)

// ErrMessageTooLarge is multipart.ErrMessageTooLarge: the same error
// ParseMultipartForm returns for a form over its memory or part limits.
var ErrMessageTooLarge = multipart.ErrMessageTooLarge

// ErrNoSpool is returned for a file part that does not fit in memory when
// the Spool has no folder. Without one the part would have to go to the
// shared temp folder, which is what this package exists to avoid.
var ErrNoSpool = errors.New("multipartspool: file part does not fit in memory and no spool folder is set")

// processToken names this process's request folders. Folders whose name
// carries another token were left by an earlier process that died
// mid-request (a finished request removes its own), so the first spill of a
// Spool removes them. Two Spools on one folder in one process share the
// token and never remove each other's live folders.
var processToken = newProcessToken()

func newProcessToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Spool is the folder a daemon spills large multipart file parts into. The
// folder must belong to this daemon alone: the first spill removes request
// folders other processes left there.
//
// A nil Spool, or one with no folder, keeps every part in memory and refuses
// (ErrNoSpool) a form whose file parts do not fit.
type Spool struct {
	dir string

	// ready latches once the folder exists with dirPerm and old request
	// folders are gone; mu single-flights that first call. Off the boot
	// path: only a request that spills pays for it. requestDir clears it
	// if the folder is deleted later.
	ready atomic.Bool
	mu    sync.Mutex
}

// New returns a Spool over dir. Nothing touches the disk until a part
// spills.
func New(dir string) *Spool {
	return &Spool{dir: strings.TrimSpace(dir)}
}

// Dir is the spool folder ("" for none).
func (s *Spool) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// ReadForm reads r's multipart/form-data body as
// r.ParseMultipartForm(maxMemory) would, with the same limits and the same
// errors for a body that is not a form. Like ParseMultipartForm it fills
// r.Form and r.PostForm (URL query values first, then the form's), so
// r.FormValue keeps working; file parts are read through the returned Form,
// not r.FormFile.
//
// On error nothing is left on disk. On success the caller must call
// Form.RemoveAll when done with the files, on every path.
func (s *Spool) ReadForm(r *http.Request, maxMemory int64) (*Form, error) {
	if r.Form == nil {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
	}
	mr, err := formReader(r)
	if err != nil {
		return nil, err
	}
	form, err := s.readForm(mr, maxMemory)
	if err != nil {
		return nil, err
	}
	if r.PostForm == nil {
		r.PostForm = make(url.Values)
	}
	for k, v := range form.Value {
		r.Form[k] = append(r.Form[k], v...)
		r.PostForm[k] = append(r.PostForm[k], v...)
	}
	return form, nil
}

// formReader is net/http's multipartReader(allowMixed=false): the checks
// ParseMultipartForm runs before it reads a byte.
func formReader(r *http.Request) (*multipart.Reader, error) {
	v := r.Header.Get("Content-Type")
	if v == "" {
		return nil, http.ErrNotMultipart
	}
	if r.Body == nil {
		return nil, errors.New("missing form body")
	}
	d, params, err := mime.ParseMediaType(v)
	if err != nil || d != "multipart/form-data" {
		return nil, http.ErrNotMultipart
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, http.ErrMissingBoundary
	}
	return multipart.NewReader(r.Body, boundary), nil
}

// readForm is mime/multipart's ReadForm with its memory accounting; only
// the spill target differs.
func (s *Spool) readForm(mr *multipart.Reader, maxMemory int64) (*Form, error) {
	form := &Form{Value: map[string][]string{}, File: map[string][]*FileHeader{}}
	// Keyed on success, not on err, so a panic mid-read (a body reader
	// that panics) still takes the request's folder with it.
	done := false
	defer func() {
		if !done {
			_ = form.RemoveAll()
		}
	}()

	if maxMemory < 0 {
		maxMemory = 0
	}
	maxFileMemoryBytes := maxMemory
	if maxFileMemoryBytes == math.MaxInt64 {
		maxFileMemoryBytes--
	}
	maxMemoryBytes := maxMemory + int64(valueMemoryExtra)
	if maxMemoryBytes <= 0 {
		maxMemoryBytes = math.MaxInt64
	}
	headerValues := int64(maxHeaderValues)
	parts := maxParts
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			done = true
			return form, nil
		}
		if err != nil {
			return nil, err
		}
		if parts <= 0 {
			return nil, ErrMessageTooLarge
		}
		parts--
		values := countHeaderValues(p.Header)
		if values > headerValues {
			return nil, ErrMessageTooLarge
		}

		name := p.FormName()
		if name == "" {
			continue
		}
		filename := p.FileName()
		maxMemoryBytes -= int64(len(name)) + mapEntryOverhead
		if maxMemoryBytes < 0 {
			return nil, ErrMessageTooLarge
		}

		var b bytes.Buffer
		if filename == "" {
			n, err := io.CopyN(&b, p, maxMemoryBytes+1)
			if err != nil && err != io.EOF {
				return nil, err
			}
			maxMemoryBytes -= n
			if maxMemoryBytes < 0 {
				return nil, ErrMessageTooLarge
			}
			form.Value[name] = append(form.Value[name], b.String())
			continue
		}

		// A file part keeps its headers, so they count against memory.
		maxMemoryBytes -= mimeHeaderSize(p.Header) + mapEntryOverhead + fileHeaderSize
		if maxMemoryBytes < 0 {
			return nil, ErrMessageTooLarge
		}
		headerValues -= values
		fh := &FileHeader{Filename: filename, Header: p.Header}
		n, err := io.CopyN(&b, p, maxFileMemoryBytes+1)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n > maxFileMemoryBytes {
			if err := s.spill(form, fh, b.Bytes(), p); err != nil {
				return nil, err
			}
		} else {
			fh.content = b.Bytes()
			fh.Size = n
			maxFileMemoryBytes -= n
			maxMemoryBytes -= n
		}
		form.File[name] = append(form.File[name], fh)
	}
}

// spill writes a part that did not fit in memory (head, already read, then
// the rest) to a file in the request's folder, made on the first spill.
func (s *Spool) spill(form *Form, fh *FileHeader, head []byte, rest io.Reader) (err error) {
	if form.dir == "" {
		dir, err := s.requestDir()
		if err != nil {
			return err
		}
		form.dir = dir
	}
	f, err := os.CreateTemp(form.dir, "part-")
	if err != nil {
		return err
	}
	// Deferred so a panicking body does not leak the descriptor either.
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	fh.path = f.Name()
	n, err := f.Write(head)
	if err == nil {
		var m int64
		m, err = io.Copy(f, rest)
		fh.Size = int64(n) + m
	}
	return err
}

// requestDir makes a private folder for one request inside the spool.
func (s *Spool) requestDir() (string, error) {
	base, err := s.ensure()
	if err != nil {
		return "", err
	}
	// MkdirTemp creates the folder 0700.
	dir, err := os.MkdirTemp(base, requestDirPrefix+processToken+"-")
	if errors.Is(err, fs.ErrNotExist) {
		// The spool folder went after the latch was set (an operator
		// freeing disk). Make it again, once, rather than refuse every
		// spill until a restart.
		s.ready.Store(false)
		if base, err = s.ensure(); err != nil {
			return "", err
		}
		dir, err = os.MkdirTemp(base, requestDirPrefix+processToken+"-")
	}
	return dir, err
}

// ensure makes the spool folder once per Spool (lazy bootstrap: the
// atomic.Bool latch with a single-flight mutex). It refuses a spool path
// that is a symlink, and tightens a folder an older release or an operator
// made with looser modes. A failure is not latched; the next spill retries.
func (s *Spool) ensure() (string, error) {
	if s == nil || s.dir == "" {
		return "", ErrNoSpool
	}
	if s.ready.Load() {
		return s.dir, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready.Load() {
		return s.dir, nil
	}
	if err := os.MkdirAll(s.dir, dirPerm); err != nil {
		return "", err
	}
	info, err := os.Lstat(s.dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("multipartspool: %s is not a folder", s.dir)
	}
	if info.Mode().Perm() != dirPerm {
		if err := os.Chmod(s.dir, dirPerm); err != nil {
			return "", err
		}
	}
	s.sweep()
	s.ready.Store(true)
	return s.dir, nil
}

// sweep removes request folders an earlier process left behind when it
// died mid-request. Best effort: a folder that will not go only costs disk.
func (s *Spool) sweep() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	own := requestDirPrefix + processToken + "-"
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, requestDirPrefix) && !strings.HasPrefix(name, own) {
			_ = os.RemoveAll(filepath.Join(s.dir, name))
		}
	}
}

func countHeaderValues(h textproto.MIMEHeader) int64 {
	var n int64
	for _, v := range h {
		n += int64(len(v))
	}
	return n
}

// mimeHeaderSize is mime/multipart's estimate of a part header's memory.
func mimeHeaderSize(h textproto.MIMEHeader) int64 {
	size := int64(400)
	for k, vs := range h {
		size += int64(len(k)) + mapEntryOverhead
		for _, v := range vs {
			size += int64(len(v))
		}
	}
	return size
}

// Form is a parsed multipart form: Value parts as strings, File parts in
// memory or in the request's spool folder.
type Form struct {
	Value map[string][]string
	File  map[string][]*FileHeader

	dir string // the request's spool folder; "" until a part spills
}

// FormFile is (*http.Request).FormFile over this form: the first file for
// key, or http.ErrMissingFile.
func (f *Form) FormFile(key string) (multipart.File, *FileHeader, error) {
	if f != nil {
		if fhs := f.File[key]; len(fhs) > 0 {
			file, err := fhs[0].Open()
			return file, fhs[0], err
		}
	}
	return nil, nil, http.ErrMissingFile
}

// RemoveAll removes the request's spool folder and every part in it. It is
// safe to call more than once, and on a nil Form.
func (f *Form) RemoveAll() error {
	if f == nil || f.dir == "" {
		return nil
	}
	return os.RemoveAll(f.dir)
}

// FileHeader describes one file part.
type FileHeader struct {
	Filename string
	Header   textproto.MIMEHeader
	Size     int64

	content []byte // the part, when it fit in memory
	path    string // the spilled part, when it did not
}

// Open opens the part for reading.
func (fh *FileHeader) Open() (multipart.File, error) {
	if fh.path != "" {
		return os.Open(fh.path)
	}
	return sectionReadCloser{io.NewSectionReader(bytes.NewReader(fh.content), 0, int64(len(fh.content)))}, nil
}

// sectionReadCloser makes an in-memory part a multipart.File.
type sectionReadCloser struct {
	*io.SectionReader
}

func (sectionReadCloser) Close() error { return nil }
