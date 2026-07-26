package netstats

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestTickEmptyContainerRefDropsBaseline(t *testing.T) {
	mfs := fstest.MapFS{
		"100/net/dev": &fstest.MapFile{Data: []byte(sampleProcNetDev)},
	}
	reader := NewReaderFS(mfs)
	lookup := &fakeLookup{pids: map[string]int{"ref": 100}}
	lister := &fakeLister{targets: []Target{{SandboxID: "sb-1", ContainerRef: "ref"}}}
	sink := &fakeSink{}
	p := NewPoller(slog.Default(), reader, lookup, lister, sink, time.Second)

	p.tick(context.Background(), time.Unix(1000, 0))
	if len(p.baselines) != 1 {
		t.Fatalf("expected baseline after first tick, got %d", len(p.baselines))
	}

	lister.targets = []Target{{SandboxID: "sb-1", ContainerRef: ""}}
	p.tick(context.Background(), time.Unix(1001, 0))
	if len(p.baselines) != 0 {
		t.Fatalf("expected baseline dropped on empty container ref, got %d", len(p.baselines))
	}
}

type scanErrorReader struct{}

func (scanErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}
func (scanErrorReader) Close() error { return nil }
func (scanErrorReader) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat not implemented")
}

func TestReadParseNetDevFailure(t *testing.T) {
	r := &Reader{}
	_, err := parseNetDev(scanErrorReader{})
	if err == nil {
		t.Fatal("expected parseNetDev failure")
	}
	_, err = r.Read(9999999)
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
}

type tcpErrorFS struct {
	dev []byte
	err error
}

type mapFile struct {
	data []byte
	off  int
}

func (f *mapFile) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

func (f *mapFile) Close() error { return nil }
func (f *mapFile) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat not implemented")
}

func (f tcpErrorFS) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, "/net/dev") {
		return &mapFile{data: f.dev}, nil
	}
	if strings.HasSuffix(name, "/net/tcp") || strings.HasSuffix(name, "/net/tcp6") {
		return nil, f.err
	}
	return nil, fs.ErrNotExist
}

func TestReadActiveTCPGenericOpenError(t *testing.T) {
	r := NewReaderFS(tcpErrorFS{
		dev: []byte(sampleProcNetDev),
		err: errors.New("tcp open failed"),
	})
	_, err := r.Read(42)
	if err == nil {
		t.Fatal("expected read failure from tcp open error")
	}
}

type closeErrTCP struct {
	data []byte
}

func (c *closeErrTCP) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

func (*closeErrTCP) Close() error { return errors.New("close failed") }
func (*closeErrTCP) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat not implemented")
}

type closeErrFS struct {
	dev []byte
}

func (f closeErrFS) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, "/net/dev") {
		return &mapFile{data: f.dev}, nil
	}
	if strings.HasSuffix(name, "/net/tcp") {
		return &closeErrTCP{data: []byte(sampleProcNetTCP)}, nil
	}
	return nil, fs.ErrNotExist
}

func TestReadActiveTCPCloseError(t *testing.T) {
	r := NewReaderFS(closeErrFS{dev: []byte(sampleProcNetDev)})
	_, err := r.Read(42)
	if err == nil {
		t.Fatal("expected close error from tcp reader")
	}
}

func TestParseNetDevEdgeCases(t *testing.T) {
	input := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
no-colon-line
    lo:    1000       1    0    0    0     0          0         0     1000       1    0    0    0     0       0          0
  eth0:    2000       1    0    0    0     0          0         0     3000       1    0    0    0     0       0          0
  eth1:    bad        1    0    0    0     0          0         0     4000       1    0    0    0     0       0          0
  eth2:    5000       1    0    0    0     0          0         0     bad        1    0    0    0     0       0          0
  eth3:    6000
`
	got, err := parseNetDev(stringReadCloser{strings.NewReader(input)})
	if err != nil {
		t.Fatalf("parseNetDev: %v", err)
	}
	// eth0 only: eth1/eth2 skipped for parse errors, eth3 too short, lo skipped.
	if got.BytesIn != 2000 || got.BytesOut != 3000 {
		t.Fatalf("counters = %+v, want 2000/3000", got)
	}
}

func TestParseProcNetTCPNoEstablished(t *testing.T) {
	input := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0200000A:BEEF 02 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 20 4 30 10 -1
`
	active, err := parseProcNetTCP(stringReadCloser{strings.NewReader(input)})
	if err != nil {
		t.Fatalf("parseProcNetTCP: %v", err)
	}
	if active {
		t.Fatal("expected no established TCP socket")
	}
}

type tcpParseErrorFS struct {
	dev []byte
}

func (f tcpParseErrorFS) Open(name string) (fs.File, error) {
	if strings.HasSuffix(name, "/net/dev") {
		return &mapFile{data: f.dev}, nil
	}
	if strings.HasSuffix(name, "/net/tcp") || strings.HasSuffix(name, "/net/tcp6") {
		return scanErrorReader{}, nil
	}
	return nil, fs.ErrNotExist
}

func TestReadActiveTCPParseError(t *testing.T) {
	r := NewReaderFS(tcpParseErrorFS{dev: []byte(sampleProcNetDev)})
	_, err := r.Read(42)
	if err == nil {
		t.Fatal("expected parse error from tcp table")
	}
}
