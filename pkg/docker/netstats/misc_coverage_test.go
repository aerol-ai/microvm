package netstats

import (
	"errors"
	"io"
	"io/fs"
)

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
