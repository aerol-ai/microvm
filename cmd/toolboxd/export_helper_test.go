package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestExportHelperRequested(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == exportHelperEnv {
				return v
			}
			return ""
		}
	}
	for _, tc := range []struct {
		pid  int
		val  string
		want bool
	}{
		{1, "1", true},
		{1, "", false},
		{1, "0", false},
		{42, "1", false}, // only as init: a sandbox's own process cannot become the helper
	} {
		if got := exportHelperRequested(tc.pid, env(tc.val)); got != tc.want {
			t.Errorf("pid %d %s=%q: %v, want %v", tc.pid, exportHelperEnv, tc.val, got, tc.want)
		}
	}
}

// exportRW is one connection: what the host sent, and what the helper wrote
// back.
type exportRW struct {
	in      *strings.Reader
	out     bytes.Buffer
	failOut bool
}

func (c *exportRW) Read(p []byte) (int, error) { return c.in.Read(p) }
func (c *exportRW) Write(p []byte) (int, error) {
	if c.failOut {
		return 0, errors.New("host gone")
	}
	return c.out.Write(p)
}

func TestServeExportConn(t *testing.T) {
	tarOf := func(w io.Writer) error { _, err := w.Write([]byte("TAR-BYTES")); return err }
	t.Run("ping, then the export", func(t *testing.T) {
		c := &exportRW{in: strings.NewReader(`{"op":"ping"}` + "\n" + `{"op":"export_rootfs"}` + "\n")}
		if err := serveExportConn(c, nil, tarOf); err != nil {
			t.Fatal(err)
		}
		if want := `{"ok":true}` + "\n" + `{"ok":true}` + "\n" + "TAR-BYTES"; c.out.String() != want {
			t.Fatalf("wrote %q, want %q", c.out.String(), want)
		}
	})
	t.Run("a disk that did not mount", func(t *testing.T) {
		c := &exportRW{in: strings.NewReader(`{"op":"export_rootfs"}` + "\n")}
		diskErr := errors.New("mount the disk copy: invalid argument")
		if err := serveExportConn(c, diskErr, tarOf); !errors.Is(err, diskErr) {
			t.Fatalf("err = %v", err)
		}
		if !strings.Contains(c.out.String(), `"error":"mount the disk copy: invalid argument"`) || strings.Contains(c.out.String(), "TAR") {
			t.Fatalf("wrote %q", c.out.String())
		}
	})
	t.Run("an unknown op, then the host leaves", func(t *testing.T) {
		c := &exportRW{in: strings.NewReader(`{"op":"adopt"}` + "\n")}
		if err := serveExportConn(c, nil, tarOf); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(c.out.String(), `unknown op \"adopt\"`) {
			t.Fatalf("wrote %q", c.out.String())
		}
	})
	t.Run("a line that is not JSON", func(t *testing.T) {
		c := &exportRW{in: strings.NewReader("garbage\n")}
		if err := serveExportConn(c, nil, tarOf); err == nil || !strings.Contains(c.out.String(), "decode") {
			t.Fatalf("err = %v, wrote %q", err, c.out.String())
		}
	})
	t.Run("a cut line", func(t *testing.T) {
		c := &exportRW{in: strings.NewReader(`{"op":"pi`)}
		if err := serveExportConn(c, nil, tarOf); err != nil {
			t.Fatal(err)
		}
	})
	for _, op := range []string{"ping", "export_rootfs", "nope"} {
		t.Run("the host goes before the "+op+" ack", func(t *testing.T) {
			c := &exportRW{in: strings.NewReader(`{"op":"` + op + `"}` + "\n"), failOut: true}
			if err := serveExportConn(c, nil, tarOf); err == nil {
				t.Fatal("no error")
			}
		})
	}
}

// A read error other than EOF ends the connection with it.
func TestServeExportConnReadError(t *testing.T) {
	r := io.MultiReader(strings.NewReader(`{"op":"pi`), exportResetReader{})
	c := struct {
		io.Reader
		io.Writer
	}{r, io.Discard}
	if err := serveExportConn(c, nil, nil); err == nil {
		t.Fatal("no error")
	}
}

type exportResetReader struct{}

func (exportResetReader) Read([]byte) (int, error) { return 0, errors.New("reset") }
