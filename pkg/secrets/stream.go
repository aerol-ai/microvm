package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Sealed streams carry a sandbox's state from one worker to another: a
// Firecracker VM's memory, a gVisor checkpoint (plans/kubernetes-v2-
// architecture.md §10.5, C21). They hold whatever the sandbox held, its
// secrets included, and run to gigabytes, so the whole-value Seal* helpers
// do not fit: those hold the plaintext in memory at once.
//
// A stream is a header and a run of chunks:
//
//	header:  "AVS1" | uint32 len | key   (the data key, sealed by the
//	                                      cluster's Cipher, bound to aad)
//	         4-byte nonce prefix
//	chunk:   uint32 len | AES-256-GCM(data key, prefix|counter, plaintext,
//	                                  aad | counter | last)
//
// Every stream has a fresh data key, so a counter nonce never repeats. The
// counter and the last flag are in each chunk's AAD: a chunk moved, dropped
// or repeated fails to open, and so does a stream cut short, because the
// reader reports the end only after a chunk sealed as the last. The caller's
// aad binds the stream to its purpose (the sandbox, its incarnation, the
// worker it is for), so one cannot be replayed as another.

const (
	streamMagic = "AVS1"
	// streamChunk is the plaintext per chunk.
	streamChunk = 64 << 10
	// streamMaxSealedChunk bounds what a reader accepts before opening it.
	streamMaxSealedChunk = streamChunk + 64
)

// ErrStreamTruncated: the stream ended before its last chunk.
var ErrStreamTruncated = errors.New("sealed stream ended before its last chunk")

func streamKeyAAD(aad []byte) []byte {
	return append([]byte("aerolvm-stream-key-v1|"), aad...)
}

func streamChunkAAD(aad []byte, counter uint64, last bool) []byte {
	out := make([]byte, 0, len(aad)+9)
	out = append(out, aad...)
	out = binary.BigEndian.AppendUint64(out, counter)
	if last {
		return append(out, 1)
	}
	return append(out, 0)
}

func streamNonce(prefix []byte, counter uint64) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

// SealWriter seals what is written to it onto an underlying writer. Close
// writes the last chunk; without it the stream does not open.
type SealWriter struct {
	w       io.Writer
	gcm     cipher.AEAD
	prefix  []byte
	aad     []byte
	buf     []byte
	counter uint64
	closed  bool
	err     error
}

// NewSealWriter starts a sealed stream on w, bound to aad, with a fresh data
// key that c seals into the header.
func NewSealWriter(w io.Writer, c *Cipher, aad []byte) (*SealWriter, error) {
	if c == nil {
		return nil, errors.New("sealed stream: no cipher")
	}
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("sealed stream: data key: %w", err)
	}
	gcm, err := newStreamGCM(dek)
	if err != nil {
		return nil, err
	}
	wrapped, err := c.EncryptWithAAD(dek, streamKeyAAD(aad))
	if err != nil {
		return nil, fmt.Errorf("sealed stream: seal the data key: %w", err)
	}
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return nil, fmt.Errorf("sealed stream: nonce: %w", err)
	}
	var hdr bytes.Buffer
	hdr.WriteString(streamMagic)
	_ = binary.Write(&hdr, binary.BigEndian, uint32(len(wrapped)))
	hdr.Write(wrapped)
	hdr.Write(prefix)
	if _, err := w.Write(hdr.Bytes()); err != nil {
		return nil, err
	}
	return &SealWriter{w: w, gcm: gcm, prefix: prefix, aad: append([]byte(nil), aad...), buf: make([]byte, 0, streamChunk)}, nil
}

func newStreamGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("sealed stream: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// Write buffers p and seals each full chunk.
func (s *SealWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.closed {
		return 0, errors.New("sealed stream: write after close")
	}
	n := 0
	for len(p) > 0 {
		take := min(streamChunk-len(s.buf), len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		n += take
		if len(s.buf) == streamChunk {
			if err := s.flush(false); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (s *SealWriter) flush(last bool) error {
	sealed := s.gcm.Seal(nil, streamNonce(s.prefix, s.counter), s.buf, streamChunkAAD(s.aad, s.counter, last))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed)))
	if _, err := s.w.Write(lenBuf[:]); err != nil {
		s.err = err
		return err
	}
	if _, err := s.w.Write(sealed); err != nil {
		s.err = err
		return err
	}
	s.counter++
	s.buf = s.buf[:0]
	return nil
}

// Close seals what is buffered as the last chunk (an empty one if nothing
// is).
func (s *SealWriter) Close() error {
	if s.closed {
		return s.err
	}
	s.closed = true
	if s.err != nil {
		return s.err
	}
	return s.flush(true)
}

// OpenReader reads a sealed stream's plaintext. It returns io.EOF only after
// the last chunk; a stream that ends before it is ErrStreamTruncated, and a
// chunk that does not open is an error.
type OpenReader struct {
	r       io.Reader
	gcm     cipher.AEAD
	prefix  []byte
	aad     []byte
	plain   []byte
	counter uint64
	done    bool
	err     error
}

// NewOpenReader reads a sealed stream's header from r, opening its data key
// with c and aad.
func NewOpenReader(r io.Reader, c *Cipher, aad []byte) (*OpenReader, error) {
	if c == nil {
		return nil, errors.New("sealed stream: no cipher")
	}
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("sealed stream: header: %w", err)
	}
	if string(hdr[:4]) != streamMagic {
		return nil, errors.New("sealed stream: not a sealed stream")
	}
	keyLen := binary.BigEndian.Uint32(hdr[4:])
	if keyLen == 0 || keyLen > 4096 {
		return nil, errors.New("sealed stream: bad key length")
	}
	wrapped := make([]byte, keyLen)
	if _, err := io.ReadFull(r, wrapped); err != nil {
		return nil, fmt.Errorf("sealed stream: key: %w", err)
	}
	dek, err := c.DecryptWithAAD(wrapped, streamKeyAAD(aad))
	if err != nil {
		return nil, fmt.Errorf("sealed stream: open the data key (wrong key, or a stream for something else): %w", err)
	}
	gcm, err := newStreamGCM(dek)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf("sealed stream: nonce: %w", err)
	}
	return &OpenReader{r: r, gcm: gcm, prefix: prefix, aad: append([]byte(nil), aad...)}, nil
}

// Read returns plaintext in order.
func (o *OpenReader) Read(p []byte) (int, error) {
	for len(o.plain) == 0 {
		if o.err != nil {
			return 0, o.err
		}
		if o.done {
			return 0, io.EOF
		}
		o.err = o.next()
	}
	n := copy(p, o.plain)
	o.plain = o.plain[n:]
	return n, nil
}

func (o *OpenReader) next() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(o.r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrStreamTruncated
		}
		return err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < uint32(o.gcm.Overhead()) || n > streamMaxSealedChunk {
		return errors.New("sealed stream: bad chunk length")
	}
	sealed := make([]byte, n)
	if _, err := io.ReadFull(o.r, sealed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrStreamTruncated
		}
		return err
	}
	nonce := streamNonce(o.prefix, o.counter)
	// A chunk opens under exactly one of the two flags; which one says
	// whether the stream ends here.
	if plain, err := o.gcm.Open(nil, nonce, sealed, streamChunkAAD(o.aad, o.counter, false)); err == nil {
		o.plain, o.counter = plain, o.counter+1
		return nil
	}
	plain, err := o.gcm.Open(nil, nonce, sealed, streamChunkAAD(o.aad, o.counter, true))
	if err != nil {
		return fmt.Errorf("sealed stream: chunk %d does not open (changed, moved or from another stream)", o.counter)
	}
	o.plain, o.counter, o.done = plain, o.counter+1, true
	return nil
}
