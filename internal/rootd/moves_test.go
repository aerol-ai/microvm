package rootd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runscwrap"
	"github.com/aerol-ai/microvm/internal/runtime/movebundle"
)

// withMoves turns gVisor checkpoint moves on in a test helper's config,
// with its moves folder beside the rig's other folders.
func withMoves(c *Config) {
	c.Policy.MovesDir = filepath.Join(filepath.Dir(filepath.Dir(c.Socket)), "state", "moves")
	c.Moves = &MovesConfig{Runsc: "/usr/local/bin/runsc", StateRoot: "/run/containerd/runsc", MaxBundleBytes: 1 << 20, MaxStaged: 2}
}

// fakeRunsc stands in for runsc checkpoint: it writes a checkpoint's files
// into the image path, unless told to fail or to write none.
type fakeRunsc struct {
	mu    sync.Mutex
	args  [][]string
	fail  bool
	write map[string]string
}

func (f *fakeRunsc) run(_ context.Context, bin string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.args = append(f.args, append([]string{bin}, args...))
	if f.fail {
		return []byte(strings.Repeat("runsc: no such sandbox ", 400)), errors.New("exit status 128")
	}
	var dir string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--image-path="); ok {
			dir = v
		}
	}
	for name, body := range f.write {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func newMoveRig(t *testing.T, mutate func(*Config)) (*rig, *fakeRunsc) {
	t.Helper()
	r := newRig(t, func(c *Config, _ *Options) {
		withMoves(c)
		if mutate != nil {
			mutate(c)
		}
	})
	f := &fakeRunsc{write: map[string]string{runscwrap.CheckpointFile: "state", "pages.img": "memory"}}
	r.srv.moves.run = f.run
	return r, f
}

// exportAll runs an export and answers its bytes.
func exportAll(ctx context.Context, c rootdpb.RootHelperClient, id string) ([]byte, error) {
	s, err := c.ExportMove(ctx, &rootdpb.ExportMoveRequest{SandboxId: id})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for {
		m, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return out.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
		out.Write(m.GetData())
	}
}

// importAll sends msgs as one import and answers the helper's reply.
func importAll(ctx context.Context, c rootdpb.RootHelperClient, msgs ...*rootdpb.ImportMoveRequest) (*rootdpb.ImportMoveResponse, error) {
	s, err := c.ImportMove(ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if err := s.Send(m); err != nil {
			break
		}
	}
	return s.CloseAndRecv()
}

// importBundle sends bundle in chunks of size n, the first naming id.
func importBundle(ctx context.Context, c rootdpb.RootHelperClient, id string, bundle []byte, n int) (*rootdpb.ImportMoveResponse, error) {
	msgs := []*rootdpb.ImportMoveRequest{{SandboxId: id}}
	for len(bundle) > 0 {
		k := min(n, len(bundle))
		msgs = append(msgs, &rootdpb.ImportMoveRequest{Data: bundle[:k]})
		bundle = bundle[k:]
	}
	return importAll(ctx, c, msgs...)
}

// TestMoveCheckpointExportImport (M1 PR 13): the helper checkpoints a
// sandbox with runsc into its own moves folder, sends that checkpoint as a
// move bundle, takes a bundle in and stages it for the restore, answers
// where, and drops each side.
func TestMoveCheckpointExportImport(t *testing.T) {
	r, f := newMoveRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	moves := r.cfg.Policy.MovesDir
	if _, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/local/bin/runsc", "--root=/run/containerd/runsc/aerolvm", "checkpoint", "--image-path=" + filepath.Join(moves, "out", "sb-1"), "--", "sb-1"}
	if len(f.args) != 1 || !slices.Equal(f.args[0], want) {
		t.Fatalf("runsc ran with %v, want %v", f.args, want)
	}
	// A sandbox ID may begin with '-': runsc takes it after "--", as the
	// container's ID, never as an option.
	if _, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "-sb-dash"}); err != nil {
		t.Fatal(err)
	}
	dash := []string{"/usr/local/bin/runsc", "--root=/run/containerd/runsc/aerolvm", "checkpoint", "--image-path=" + filepath.Join(moves, "out", "-sb-dash"), "--", "-sb-dash"}
	if len(f.args) != 2 || !slices.Equal(f.args[1], dash) {
		t.Fatalf("runsc ran with %v, want %v", f.args, dash)
	}
	if _, err := c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: "-sb-dash", Sides: []rootdpb.MoveSide{rootdpb.MoveSide_MOVE_SIDE_OUT}}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(moves, "out"), filepath.Join(moves, "in"), filepath.Join(moves, "out", "sb-1")} {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v, want a folder of mode 0700", dir, fi, err)
		}
	}
	bundle, err := exportAll(ctx, c, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	// The bundle is the format single mode sends: a single node reads it.
	staging := t.TempDir()
	if m, err := movebundle.ReadDir(ctx, bytes.NewReader(bundle), staging, "sb-1", movebundle.NoBound); err != nil || !slices.Equal(m.Files, []string{runscwrap.CheckpointFile, "pages.img"}) {
		t.Fatalf("the export is not a move bundle: %v %v", m, err)
	}
	// And a bundle a single node wrote is one the helper takes, here in
	// small chunks.
	resp, err := importBundle(ctx, c, "sb-1", bundle, 100)
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(moves, "in", "sb-1")
	if resp.GetRestorePath() != staged {
		t.Fatalf("restore path %q", resp.GetRestorePath())
	}
	if b, err := os.ReadFile(filepath.Join(staged, "pages.img")); err != nil || string(b) != "memory" {
		t.Fatalf("staged pages: %q %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(staged, runscwrap.CheckpointFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("staged checkpoint: %v %v", fi, err)
	}
	got, err := c.StagedMove(ctx, &rootdpb.StagedMoveRequest{SandboxId: "sb-1"})
	if err != nil || got.GetRestorePath() != staged {
		t.Fatalf("StagedMove = %v, %v", got, err)
	}
	// An import again replaces the staged one.
	if _, err := importBundle(ctx, c, "sb-1", bundle, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: "sb-1", Sides: []rootdpb.MoveSide{rootdpb.MoveSide_MOVE_SIDE_IN}}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.StagedMove(ctx, &rootdpb.StagedMoveRequest{SandboxId: "sb-1"}); err != nil || got.GetRestorePath() != "" {
		t.Fatalf("after the drop: %v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(moves, "out", "sb-1")); err != nil {
		t.Fatalf("the drop of the in side took the out side: %v", err)
	}
	if _, err := c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: "sb-1", Sides: []rootdpb.MoveSide{rootdpb.MoveSide_MOVE_SIDE_OUT, rootdpb.MoveSide_MOVE_SIDE_IN}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moves, "out", "sb-1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the out side stayed: %v", err)
	}
	if _, err := exportAll(ctx, c, "sb-1"); status.Code(err) != codes.NotFound {
		t.Fatalf("an export with no checkpoint = %v, want NotFound", err)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}

// TestMoveCheckpointFailures: a failed runsc, or one that saved nothing,
// leaves no folder; a checkpoint again replaces the last one.
func TestMoveCheckpointFailures(t *testing.T) {
	r, f := newMoveRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	out := filepath.Join(r.cfg.Policy.MovesDir, "out", "sb-1")
	f.fail = true
	_, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-1"})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "no such sandbox") || len(err.Error()) > runscOutputMax+512 {
		t.Fatalf("a failed runsc: %v", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed checkpoint left its folder: %v", err)
	}
	f.fail, f.write = false, map[string]string{"pages.img": "x"}
	if _, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-1"}); err == nil || !strings.Contains(err.Error(), "no checkpoint") {
		t.Fatalf("a checkpoint with no checkpoint file: %v", err)
	}
	f.write = map[string]string{runscwrap.CheckpointFile: "one", "old.img": "x"}
	if _, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	f.write = map[string]string{runscwrap.CheckpointFile: "two"}
	if _, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "old.img")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the last checkpoint's file stayed: %v", err)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("a failed runsc is no refusal: %v", r.refused())
	}
}

// tarEntry is one entry of a tarBundle.
type tarEntry struct {
	name, body, link string
	kind             byte
}

func tarBundle(t *testing.T, manifest *movebundle.Manifest, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if manifest != nil {
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: movebundle.ManifestName, Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(raw)
	}
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o600, Typeflag: kind, Linkname: e.link}
		if kind == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if kind == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestMoveBrokenAgentImports: every bundle the helper must not stage is
// refused as a broken agent's (a security event, reason move_bundle or
// bad_request), and leaves nothing in the moves folder.
func TestMoveBrokenAgentImports(t *testing.T) {
	ckpt := tarEntry{name: runscwrap.CheckpointFile, body: "state"}
	man := func(id string, files ...string) *movebundle.Manifest {
		return &movebundle.Manifest{Version: 1, SandboxID: id, Files: files}
	}
	good := tarBundle(t, man("sb-1", ckpt.name), ckpt)
	big := tarBundle(t, man("sb-1", ckpt.name), tarEntry{name: ckpt.name, body: strings.Repeat("s", 4000)})
	for _, tc := range []struct {
		name   string
		id     string
		msgs   func() []*rootdpb.ImportMoveRequest
		reason string
	}{
		{"a sandbox ID with ../", "../sb-1", nil, ReasonBadRequest},
		{"a sandbox ID that is a path", "/etc", nil, ReasonBadRequest},
		{"a manifest for another sandbox", "sb-1", bundleMsgs(tarBundle(t, man("sb-2", ckpt.name), ckpt)), string(rootpolicy.RuleMoveBundle)},
		{"a file whose name climbs out", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", "../escape"), tarEntry{name: "../escape", body: "x"})), string(rootpolicy.RuleMoveBundle)},
		{"a file name with a folder", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", "a/b"), tarEntry{name: "a/b", body: "x"})), string(rootpolicy.RuleMoveBundle)},
		{"a link", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", ckpt.name), tarEntry{name: ckpt.name, kind: tar.TypeSymlink, link: "/etc/shadow"})), string(rootpolicy.RuleMoveBundle)},
		{"a hard link", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", ckpt.name), tarEntry{name: ckpt.name, kind: tar.TypeLink, link: "/etc/shadow"})), string(rootpolicy.RuleMoveBundle)},
		{"a device", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", ckpt.name), tarEntry{name: ckpt.name, kind: tar.TypeChar})), string(rootpolicy.RuleMoveBundle)},
		{"a file the manifest does not name", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", ckpt.name), ckpt, tarEntry{name: "extra", body: "x"})), string(rootpolicy.RuleMoveBundle)},
		{"a file twice", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", ckpt.name), ckpt, ckpt)), string(rootpolicy.RuleMoveBundle)},
		{"no manifest", "sb-1", bundleMsgs(tarBundle(t, nil, ckpt)), string(rootpolicy.RuleMoveBundle)},
		{"no checkpoint in it", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", "pages.img"), tarEntry{name: "pages.img", body: "x"})), string(rootpolicy.RuleMoveBundle)},
		{"not a tar", "sb-1", bundleMsgs([]byte("this is not a bundle")), string(rootpolicy.RuleMoveBundle)},
		// A file cut short (a bundle that ends at a file's end, short of the
		// tar's end marker, holds every file whole, and is taken).
		{"a file cut short", "sb-1", bundleMsgs(big[:len(big)-1024-1500]), string(rootpolicy.RuleMoveBundle)},
		{"bytes after the bundle", "sb-1", bundleMsgs(append(slices.Clone(good), 'x')), string(rootpolicy.RuleMoveBundle)},
		{"larger than the node takes", "sb-1", bundleMsgs(tarBundle(t, man("sb-1", ckpt.name), tarEntry{name: ckpt.name, body: strings.Repeat("x", 1<<20)})), string(rootpolicy.RuleMoveBundle)},
		// A few KiB of stream for a file of 64 MiB, under a 1 MiB bound:
		// bundle sizes are bounded by what is written, and sparse entries
		// are refused.
		{"a sparse entry", "sb-1", bundleMsgs(sparseMoveBundle(t, "sb-1", ckpt.name, 64<<20)), string(rootpolicy.RuleMoveBundle)},
		// A whole bundle past the bound, all in the first message: the bound
		// holds before a byte of it is written.
		{"a first message past the bound", "sb-1", func() []*rootdpb.ImportMoveRequest {
			return []*rootdpb.ImportMoveRequest{{SandboxId: "sb-1", Data: tarBundle(t, man("sb-1", ckpt.name), tarEntry{name: ckpt.name, body: strings.Repeat("x", 1<<20)})}}
		}, string(rootpolicy.RuleMoveBundle)},
		{"a later message naming a sandbox", "sb-1", func() []*rootdpb.ImportMoveRequest {
			return []*rootdpb.ImportMoveRequest{{SandboxId: "sb-1"}, {SandboxId: "sb-2", Data: good}}
		}, string(rootpolicy.RuleMoveBundle)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newMoveRig(t, nil)
			c := rootdpb.NewRootHelperClient(r.conn)
			msgs := []*rootdpb.ImportMoveRequest{{SandboxId: tc.id, Data: good}}
			if tc.msgs != nil {
				msgs = tc.msgs()
				if msgs[0].GetSandboxId() == "" {
					msgs = append([]*rootdpb.ImportMoveRequest{{SandboxId: tc.id}}, msgs...)
				}
			}
			_, err := importAll(callCtx(t), c, msgs...)
			if reason, refused := rootdpb.RefusalReason(err); !refused || reason != tc.reason {
				t.Fatalf("import = %v, want a refusal %q", err, tc.reason)
			}
			if got := r.refused(); len(got) != 1 || got[0].Method != rootdpb.RootHelper_ImportMove_FullMethodName {
				t.Fatalf("refusals heard %v", got)
			}
			left, _ := os.ReadDir(filepath.Join(r.cfg.Policy.MovesDir, "in"))
			if len(left) != 0 {
				t.Fatalf("a refused import left %v", left)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(r.cfg.Policy.MovesDir), "escape")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a file was written outside the moves folder")
			}
		})
	}
}

// sparseMoveBundle is a bundle whose one file is a PAX sparse entry of size
// bytes, all of it a hole, so its stream is a few headers. Go's tar writer
// does not write sparse entries: the blocks are built here, as in
// movebundle's own test.
func sparseMoveBundle(t *testing.T, id, name string, size int64) []byte {
	t.Helper()
	out := tarBundle(t, &movebundle.Manifest{Version: 1, SandboxID: id, Files: []string{name}})
	out = out[:len(out)-1024] // the end marker goes after the sparse entry
	record := func(k, v string) string {
		body := " " + k + "=" + v + "\n"
		n := len(body) + 1
		for len(fmt.Sprint(n))+len(body) != n {
			n = len(fmt.Sprint(n)) + len(body)
		}
		return fmt.Sprint(n) + body
	}
	block := func(name string, typeflag byte, size int64) []byte {
		b := make([]byte, 512)
		copy(b[0:100], name)
		copy(b[100:108], "0000600\x00")
		copy(b[108:116], "0000000\x00")
		copy(b[116:124], "0000000\x00")
		copy(b[124:136], fmt.Sprintf("%011o\x00", size))
		copy(b[136:148], fmt.Sprintf("%011o\x00", 0))
		copy(b[148:156], "        ")
		b[156] = typeflag
		copy(b[257:263], "ustar\x00")
		copy(b[263:265], "00")
		var sum int64
		for _, c := range b {
			sum += int64(c)
		}
		copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
		return b
	}
	pad := func(b []byte) []byte { return append(b, make([]byte, (512-len(b)%512)%512)...) }
	pax := record("GNU.sparse.major", "1") + record("GNU.sparse.minor", "0") +
		record("GNU.sparse.name", name) + record("GNU.sparse.realsize", fmt.Sprint(size))
	out = append(out, block("PaxHeaders/"+name, tar.TypeXHeader, int64(len(pax)))...)
	out = append(out, pad([]byte(pax))...)
	out = append(out, block("GNUSparseFile.0/"+name, tar.TypeReg, 512)...)
	out = append(out, pad([]byte("0\n"))...)
	return append(out, make([]byte, 1024)...)
}

// bundleMsgs is a bundle as the import's later messages, 512 bytes each.
func bundleMsgs(b []byte) func() []*rootdpb.ImportMoveRequest {
	return func() []*rootdpb.ImportMoveRequest {
		var out []*rootdpb.ImportMoveRequest
		for len(b) > 0 {
			k := min(512, len(b))
			out = append(out, &rootdpb.ImportMoveRequest{Data: b[:k]})
			b = b[k:]
		}
		return out
	}
}

// TestMoveBrokenAgentCalls: the other move calls refuse a hostile sandbox
// ID or side, and touch nothing.
func TestMoveBrokenAgentCalls(t *testing.T) {
	r, f := newMoveRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	for _, id := range []string{"../sb-1", "sb-1/../../etc", "", ".hidden", strings.Repeat("a", 300)} {
		_, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: id})
		if reason, refused := rootdpb.RefusalReason(err); !refused || reason != ReasonBadRequest {
			t.Fatalf("CheckpointMove(%q) = %v", id, err)
		}
		if _, err := exportAll(ctx, c, id); err == nil {
			t.Fatalf("ExportMove(%q) worked", id)
		}
		if _, err := c.StagedMove(ctx, &rootdpb.StagedMoveRequest{SandboxId: id}); err == nil {
			t.Fatalf("StagedMove(%q) worked", id)
		}
		if _, err := c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: id, Sides: []rootdpb.MoveSide{rootdpb.MoveSide_MOVE_SIDE_IN}}); err == nil {
			t.Fatalf("DropMove(%q) worked", id)
		}
	}
	if len(f.args) != 0 {
		t.Fatalf("runsc ran for a hostile ID: %v", f.args)
	}
	for _, sides := range [][]rootdpb.MoveSide{nil, {rootdpb.MoveSide_MOVE_SIDE_UNSPECIFIED}, {rootdpb.MoveSide(9)}, {rootdpb.MoveSide_MOVE_SIDE_OUT, rootdpb.MoveSide(9)}} {
		_, err := c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: "sb-1", Sides: sides})
		if reason, refused := rootdpb.RefusalReason(err); !refused || reason != ReasonBadRequest {
			t.Fatalf("DropMove sides %v = %v", sides, err)
		}
	}
}

// TestMoveStagedBound: the bundles staged or arriving are bounded, busy
// past the bound (no refusal); a sandbox's own staged bundle does not count
// against its next import, which replaces it.
func TestMoveStagedBound(t *testing.T) {
	r, f := newMoveRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	f.write = map[string]string{runscwrap.CheckpointFile: "s"}
	bundleOf := func(id string) []byte {
		ckpt := tarEntry{name: runscwrap.CheckpointFile, body: "state of " + id}
		return tarBundle(t, &movebundle.Manifest{Version: 1, SandboxID: id, Files: []string{ckpt.name}}, ckpt)
	}
	for _, id := range []string{"sb-a", "sb-b"} {
		if _, err := importBundle(ctx, c, id, bundleOf(id), 4096); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := importBundle(ctx, c, "sb-c", bundleOf("sb-c"), 4096); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a third import = %v, want ResourceExhausted", err)
	}
	if _, err := importBundle(ctx, c, "sb-a", bundleOf("sb-a"), 4096); err != nil {
		t.Fatalf("a staged sandbox's import again: %v", err)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("a full node is no refusal: %v", r.refused())
	}
}

// TestMoveImportCutByTheAgent: an import the agent cancels (its source
// failed) is no refusal and stages nothing.
func TestMoveImportCutByTheAgent(t *testing.T) {
	r, _ := newMoveRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx, cancel := context.WithCancel(context.Background())
	s, err := c.ImportMove(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(&rootdpb.ImportMoveRequest{SandboxId: "sb-1", Data: []byte("partial")}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := s.CloseAndRecv(); err == nil {
		t.Fatal("a cancelled import was staged")
	}
	in := filepath.Join(r.cfg.Policy.MovesDir, "in")
	deadline := time.Now().Add(5 * time.Second)
	for {
		left, _ := os.ReadDir(in)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a cancelled import left %v", left)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("a cancelled import is no refusal: %v", r.refused())
	}
}

// TestMoveCallsNeedTheSetting: a helper whose own settings take no moves
// lists no move call and answers each as one it lacks, not a refusal.
func TestMoveCallsNeedTheSetting(t *testing.T) {
	r := newRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	v, err := c.Version(ctx, &rootdpb.VersionRequest{})
	if err != nil || slices.ContainsFunc(v.GetFeatures(), func(f string) bool { return slices.Contains(moveFeatures, f) }) {
		t.Fatalf("features %v (%v)", v.GetFeatures(), err)
	}
	_, err1 := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-1"})
	_, err2 := exportAll(ctx, c, "sb-1")
	_, err3 := importAll(ctx, c, &rootdpb.ImportMoveRequest{SandboxId: "sb-1"})
	_, err4 := c.StagedMove(ctx, &rootdpb.StagedMoveRequest{SandboxId: "sb-1"})
	_, err5 := c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: "sb-1"})
	for i, err := range []error{err1, err2, err3, err4, err5} {
		if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "SB_GVISOR_CHECKPOINT_MOVES") {
			t.Fatalf("call %d = %v", i, err)
		}
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}

// listed is a container list for the sweep.
type listed map[string]bool

func (l listed) ContainerIDs(context.Context) (map[string]bool, error) { return l, nil }

// TestMoveSweep: the sweep takes a staged bundle once old, its container
// or not, and an old checkpoint once its container is gone; nothing young.
func TestMoveSweep(t *testing.T) {
	r, _ := newMoveRig(t, nil)
	moves := r.cfg.Policy.MovesDir
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{"out/sb-live", "out/sb-gone", "out/sb-young", "in/sb-live", "in/sb-gone", "in/sb-young", "in/not an id"} {
		dir := filepath.Join(moves, p)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(p, "young") {
			if err := os.Chtimes(dir, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	removed, err := r.srv.SweepMoves(context.Background(), listed{"sb-live": true}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(removed)
	if !slices.Equal(removed, []string{"sb-gone", "sb-gone", "sb-live"}) {
		t.Fatalf("removed %v", removed)
	}
	for _, p := range []string{"out/sb-live", "out/sb-young", "in/sb-young", "in/not an id"} {
		if _, err := os.Stat(filepath.Join(moves, p)); err != nil {
			t.Fatalf("%s went: %v", p, err)
		}
	}
	// A helper with no moves sweeps none.
	if got, err := newRig(t, nil).srv.SweepMoves(context.Background(), listed{}, 0); err != nil || got != nil {
		t.Fatalf("no moves: %v %v", got, err)
	}
}

// TestNewMoveCalls: the helper's moves folder is root's alone, made where
// missing; one someone else can write stops the helper; an import a crash
// cut short goes at start.
func TestNewMoveCalls(t *testing.T) {
	cfg := testConfig(t)
	withMoves(&cfg)
	left := filepath.Join(cfg.Policy.MovesDir, "in", ".import.0123456789abcdef")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	m, err := newMoveCalls(cfg, &keyedLocks{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.close()
	m.close()
	if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the cut import stayed: %v", err)
	}
	if err := os.Chmod(cfg.Policy.MovesDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := newMoveCalls(cfg, &keyedLocks{}, nil); err == nil || !strings.Contains(err.Error(), "moves folder") {
		t.Fatalf("a moves folder others can write: %v", err)
	}
	if m, err := newMoveCalls(testConfig(t), &keyedLocks{}, nil); m != nil || err != nil {
		t.Fatalf("no moves: %v %v", m, err)
	}
}

func TestMovesFromEnv(t *testing.T) {
	agent := []string{"/var/lib/sandboxd"}
	path := func(env map[string]string) func(k, def string) string {
		return func(k, def string) string {
			if v := env[k]; v != "" {
				return v
			}
			return def
		}
	}
	limits := rootpolicy.Limits{MemoryBytes: 8 << 30}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want *MovesConfig
		err  string
	}{
		{"off", map[string]string{}, nil, ""},
		{"on, the defaults", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true"},
			&MovesConfig{Runsc: defaultRunsc, StateRoot: defaultRunscStateRoot, MaxBundleBytes: 16 << 30, MaxStaged: defaultMaxStagedMoves}, ""},
		{"on, set", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "1", "SB_ROOTD_RUNSC": "/opt/gvisor/runsc", "SB_ROOTD_RUNSC_ROOT": "/run/runsc",
			"SB_ROOTD_MOVE_MAX_BYTES": "1048576", "SB_ROOTD_MOVE_MAX_STAGED": "3"},
			&MovesConfig{Runsc: "/opt/gvisor/runsc", StateRoot: "/run/runsc", MaxBundleBytes: 1 << 20, MaxStaged: 3}, ""},
		{"a bad setting", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "maybe"}, nil, "SB_GVISOR_CHECKPOINT_MOVES"},
		{"a bad size", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true", "SB_ROOTD_MOVE_MAX_BYTES": "-1"}, nil, "SB_ROOTD_MOVE_MAX_BYTES"},
		{"a size past int64", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true", "SB_ROOTD_MOVE_MAX_BYTES": "9223372036854775808"}, nil, "SB_ROOTD_MOVE_MAX_BYTES"},
		{"a bad count", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true", "SB_ROOTD_MOVE_MAX_STAGED": "many"}, nil, "SB_ROOTD_MOVE_MAX_STAGED"},
		{"runsc in the agent's folder", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true", "SB_ROOTD_RUNSC": "/var/lib/sandboxd/bin/runsc"}, nil, "which the agent writes"},
		{"runsc through a merged /usr's link", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true", "SB_ROOTD_RUNSC": "/sbin/runsc"}, nil, "SB_ROOTD_RUNSC: /sbin/runsc is under /sbin"},
		{"runsc's state in the agent's folder", map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true", "SB_ROOTD_RUNSC_ROOT": "/var/lib/sandboxd"}, nil, "which the agent writes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := movesFromEnv(func(k string) string { return tc.env[k] }, path(tc.env), limits, agent)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
				t.Fatalf("= %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	// A node whose memory doubled would overflow takes the most there is.
	got, err := movesFromEnv(func(k string) string { return map[string]string{"SB_GVISOR_CHECKPOINT_MOVES": "true"}[k] }, path(nil),
		rootpolicy.Limits{MemoryBytes: math.MaxInt64/2 + 1}, agent)
	if err != nil || got.MaxBundleBytes != math.MaxInt64 {
		t.Fatalf("= %+v, %v", got, err)
	}
	for _, bad := range []MovesConfig{
		{Runsc: "runsc", StateRoot: "/run/runsc", MaxBundleBytes: 1, MaxStaged: 1},
		{Runsc: "/bin/runsc", StateRoot: "/run/../runsc", MaxBundleBytes: 1, MaxStaged: 1},
		{Runsc: "/bin/runsc", StateRoot: "/", MaxBundleBytes: 1, MaxStaged: 1},
		{Runsc: "/bin/runsc", StateRoot: "/run/runsc", MaxBundleBytes: 0, MaxStaged: 1},
		{Runsc: "/bin/runsc", StateRoot: "/run/runsc", MaxBundleBytes: 1, MaxStaged: 0},
		{Runsc: "/bin/runsc", StateRoot: "/run/runsc", MaxBundleBytes: 1, MaxStaged: maxStagedMoves + 1},
	} {
		if err := bad.validate(); err == nil {
			t.Fatalf("%+v validated", bad)
		}
	}
	// The helper's own config check takes the move settings too.
	cfg := testConfig(t)
	withMoves(&cfg)
	cfg.Moves.MaxStaged = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("a config with no room for a bundle validated")
	}
}

// TestRunRunscEnv: runsc runs with an environment of its own; nothing of
// the helper's reaches it.
func TestRunRunscEnv(t *testing.T) {
	t.Setenv("AEROL_HELPER_ONLY", "secret")
	out, err := runRunsc(context.Background(), "/bin/sh", "-c", `echo "$PATH|$AEROL_HELPER_ONLY"`)
	if err != nil || strings.TrimSpace(string(out)) != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|" {
		t.Fatalf("runsc's environment: %q %v", out, err)
	}
}

// TestImportErr: which import failures are a broken agent's (refusals)
// and which are not.
func TestImportErr(t *testing.T) {
	m := &moveCalls{cfg: MovesConfig{MaxBundleBytes: 10}}
	live := context.Background()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	skew := errSkew("a newer agent's field")
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		err    error
		reason string
		code   codes.Code
	}{
		{"too large", live, errMoveTooLarge, string(rootpolicy.RuleMoveBundle), codes.InvalidArgument},
		// Bytes written past the bound read as the bound's own refusal.
		{"its files too large", live, fmt.Errorf("%q: %w", "pages.img", movebundle.ErrTooLarge), string(rootpolicy.RuleMoveBundle), codes.InvalidArgument},
		{"not a bundle", live, errors.New("the manifest must come first"), string(rootpolicy.RuleMoveBundle), codes.InvalidArgument},
		{"the stream broke", live, &streamErr{err: io.ErrClosedPipe}, "", codes.Internal},
		{"the caller gave up", gone, errors.New("the manifest must come first"), "", codes.Canceled},
		{"the disk is full", live, &os.PathError{Op: "write", Path: "x", Err: errors.New("no space left on device")}, "", codes.Internal},
		{"a newer agent's field", live, skew, "", codes.Unimplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			h := helper{log: r.srv.log, onRefusal: r.srv.onRefusal}
			_, err := answer(tc.ctx, h, rootdpb.RootHelper_ImportMove_FullMethodName, struct{}{}, m.importErr(tc.ctx, "sb-1", tc.err))
			reason, refused := rootdpb.RefusalReason(err)
			if refused != (tc.reason != "") || reason != tc.reason || status.Code(err) != tc.code {
				t.Fatalf("%v: refused %v %q, code %v; want %q %v", err, refused, reason, status.Code(err), tc.reason, tc.code)
			}
			if strings.HasSuffix(tc.name, "too large") && !strings.Contains(err.Error(), "the move bundle is more than 10 bytes") {
				t.Fatalf("%v: want the bound's refusal", err)
			}
		})
	}
	if e := (&streamErr{err: io.ErrClosedPipe}); !errors.Is(e, io.ErrClosedPipe) || !strings.Contains(e.Error(), "import stream") {
		t.Fatalf("streamErr %v", e)
	}
}

// TestMoveImportUnknownField: a later message with a field this helper
// does not know is a newer agent's, answered Unimplemented, not refused.
func TestMoveImportUnknownField(t *testing.T) {
	r, _ := newMoveRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	later := &rootdpb.ImportMoveRequest{Data: []byte("x")}
	later.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	first := &rootdpb.ImportMoveRequest{SandboxId: "sb-1"}
	if _, err := importAll(callCtx(t), c, first, later); status.Code(err) != codes.Unimplemented {
		t.Fatalf("a later message's unknown field = %v", err)
	}
	first.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	if _, err := importAll(callCtx(t), c, first); status.Code(err) != codes.Unimplemented {
		t.Fatalf("a first message's unknown field = %v", err)
	}
	ex := &rootdpb.ExportMoveRequest{SandboxId: "sb-1"}
	ex.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	if _, err := exportAll(callCtx(t), c, ex.GetSandboxId()); status.Code(err) != codes.NotFound {
		t.Fatalf("export: %v", err)
	}
	s, err := c.ExportMove(callCtx(t), ex)
	if err == nil {
		_, err = s.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("an export request's unknown field = %v", err)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}
