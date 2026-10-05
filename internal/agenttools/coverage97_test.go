package agenttools

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestHeadTailSplitsOneLargeWriteAndTrimsRunes(t *testing.T) {
	// The tail is already partly full, and the next write is bigger than the
	// room left in it but smaller than the tail itself, so the copy has to
	// fill the tail and then walk the ring. A split rune at the tail's new
	// start is trimmed.
	h := newHeadTail(16) // head 4, tail 12
	_, _ = h.Write([]byte("01234567"))
	_, _ = h.Write(append([]byte{0x80, 0x80}, []byte("abcdefghij")...))
	got := h.String()
	if !h.Truncated() || h.Dropped() <= 0 || strings.Contains(got, string([]byte{0x80})) {
		t.Fatalf("bound = trunc %v dropped %d %q", h.Truncated(), h.Dropped(), got)
	}
}

func TestCoverage97FileAndProcessFailures(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	created, err := tools.GetOrCreate(ctx, CreateSpec{Name: "box", Image: "img"})
	if err != nil {
		t.Fatal(err)
	}
	sb := created.Sandbox
	wasmCreated, err := tools.GetOrCreate(ctx, CreateSpec{Name: "wasm", Image: "mod.wasm", Runtime: models.RuntimeWasm})
	if err != nil {
		t.Fatal(err)
	}
	wasm := wasmCreated.Sandbox
	if _, err := tools.SearchFiles(ctx, wasm, "/", "*.go"); err == nil {
		t.Fatal("wasm search succeeded")
	}
	if _, err := tools.SearchFiles(ctx, sb, "/", " "); err == nil {
		t.Fatal("blank search pattern succeeded")
	}
	if _, err := tools.GrepFiles(ctx, sb, "/", ""); err == nil {
		t.Fatal("blank grep pattern succeeded")
	}
	if _, err := tools.StartProcess(ctx, sb, " ", "", nil); err == nil {
		t.Fatal("blank command succeeded")
	}
	if _, err := tools.ProcessLogs(ctx, sb, " ", 0); err == nil {
		t.Fatal("blank session succeeded")
	}
	if err := tools.StopProcess(ctx, sb, " "); err == nil {
		t.Fatal("blank stop succeeded")
	}

	fake.FailToolbox = true
	fake.FailSessions = true
	if err := tools.WriteFile(ctx, sb, "/a.txt", "x"); err == nil {
		t.Fatal("write against a failing toolbox succeeded")
	}
	if _, err := tools.ListFiles(ctx, sb, "/"); err == nil {
		t.Fatal("list against a failing toolbox succeeded")
	}
	if _, err := tools.SearchFiles(ctx, sb, "/", "*.go"); err == nil {
		t.Fatal("search against a failing toolbox succeeded")
	}
	if _, err := tools.GrepFiles(ctx, sb, "/", "x"); err == nil {
		t.Fatal("grep against a failing toolbox succeeded")
	}
	if _, err := tools.StartProcess(ctx, sb, "sleep 1", "", nil); err == nil {
		t.Fatal("start against failing sessions succeeded")
	}
	if err := tools.StopProcess(ctx, sb, "ses-1"); err == nil {
		t.Fatal("stop against failing sessions succeeded")
	}
}

func TestCreateConflictOtherThanNameAndNilWarn(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	tools.warnIfDifferent(nil, CreateSpec{Image: "other"})

	fake.ConflictAlways = true
	_, err := tools.GetOrCreate(context.Background(), CreateSpec{Name: "box", Image: "img"})
	if !IsCode(err, CodeConflict) {
		t.Fatalf("non-name conflict = %v", err)
	}
}

func TestFileInfoDecodeFailureStillReportsBinary(t *testing.T) {
	tools, fake, _ := newTestTools(t, SourceCLI)
	sb := fake.AddSandbox(models.Sandbox{Name: "box"})
	fake.PutFile(sb.ID, "/bin.dat", []byte{0x00, 0x01, 0x02, 0x03})
	fake.BadFileInfo = true
	target, err := tools.Target(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	_, err = tools.ReadFile(context.Background(), target, "/bin.dat", 1, 10)
	if !IsCode(err, CodeBinaryFile) {
		t.Fatalf("binary read = %v", err)
	}
}
