package runloop

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFileRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	base := "/" + devbox.ID

	var detail executionDetailView
	expectStatus(t, env.do(t, http.MethodPost, base+"/write_file_contents", `{"file_path":"notes/a.txt","contents":"hi \"there\"\n"}`, &detail), http.StatusOK)
	if detail.DevboxID != devbox.ID || detail.ExitStatus != 0 {
		t.Fatalf("write = %+v", detail)
	}
	// Relative paths are anchored at the devbox home directory.
	if _, ok := env.toolbox.files["/home/user/notes/a.txt"]; !ok {
		t.Fatalf("file not written under $HOME: %v", keys(env.toolbox.files))
	}

	rr := env.do(t, http.MethodPost, base+"/read_file_contents", `{"file_path":"~/notes/a.txt"}`, nil)
	expectStatus(t, rr, http.StatusOK)
	// Raw text, not a JSON string: Python returns the body verbatim.
	if rr.Body.String() != "hi \"there\"\n" || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("read = %q (%s)", rr.Body.String(), rr.Header().Get("Content-Type"))
	}
	rr = env.do(t, http.MethodPost, base+"/download_file", `{"path":"/home/user/notes/a.txt"}`, nil)
	expectStatus(t, rr, http.StatusOK)
	if rr.Body.String() != "hi \"there\"\n" || rr.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("download = %q", rr.Body.String())
	}

	expectStatus(t, env.do(t, http.MethodPost, base+"/read_file_contents", `{"file_path":"missing.txt"}`, nil), http.StatusNotFound)
	expectStatus(t, env.do(t, http.MethodPost, base+"/read_file_contents", `{"file_path":""}`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, base+"/write_file_contents", `{`, nil), http.StatusBadRequest)
	expectStatus(t, env.do(t, http.MethodPost, base+"/download_file", `{`, nil), http.StatusBadRequest)
}

func TestUploadFile(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	// `file` before `path`: the facade must not depend on part order.
	part, _ := form.CreateFormFile("file", "data.bin")
	_, _ = part.Write([]byte{0, 1, 2, 3})
	_ = form.WriteField("path", "/tmp/data.bin")
	_ = form.Close()

	req := httptest.NewRequest(http.MethodPost, devboxesPath+"/"+devbox.ID+"/upload_file", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	expectStatus(t, rr, http.StatusOK)
	if got := env.toolbox.files["/tmp/data.bin"]; !bytes.Equal(got, []byte{0, 1, 2, 3}) {
		t.Fatalf("uploaded = %v", got)
	}

	// No file part.
	body.Reset()
	form = multipart.NewWriter(&body)
	_ = form.WriteField("path", "x")
	_ = form.Close()
	req = httptest.NewRequest(http.MethodPost, devboxesPath+"/"+devbox.ID+"/upload_file", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	rr = httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	expectStatus(t, rr, http.StatusBadRequest)

	// Not multipart at all.
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/upload_file", `{}`, nil), http.StatusBadRequest)
}

func TestHomeDirFailure(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	env.toolbox.setFailNext("/process/execute", http.StatusInternalServerError)
	rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/read_file_contents", `{"file_path":"rel.txt"}`, nil)
	expectStatus(t, rr, http.StatusBadGateway)
	env.toolbox.setFailNext("/files/upload", http.StatusInternalServerError)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/write_file_contents", `{"file_path":"/abs.txt","contents":"x"}`, nil), http.StatusBadGateway)
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSnapshotLifecycle(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")

	var snap snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{"name":"base","metadata":{"stage":"dev"},"commit_message":"first"}`, &snap, "X-Request-Id", "snap-1"), http.StatusOK)
	if !strings.HasPrefix(snap.ID, snapshotPrefix+devbox.ID+".") || snap.SourceDevboxID != devbox.ID {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.Name == nil || *snap.Name != "base" || snap.Metadata["stage"] != "dev" || snap.CommitMessage == nil {
		t.Fatalf("attributes = %+v", snap)
	}
	// A retried snapshot request lands on the same snapshot.
	var again snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{"name":"base","metadata":{"stage":"dev"},"commit_message":"first"}`, &again, "X-Request-Id", "snap-1"), http.StatusOK)
	if again.ID != snap.ID {
		t.Fatalf("retry made a new snapshot: %s vs %s", again.ID, snap.ID)
	}

	var status snapshotStatusView
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, &status), http.StatusOK)
	if status.Status != "complete" || status.Snapshot == nil || status.Snapshot.ID != snap.ID {
		t.Fatalf("status = %+v", status)
	}

	var list listSnapshotsResponse
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?devbox_id="+devbox.ID+"&metadata[stage]=dev", nil, &list), http.StatusOK)
	if len(list.Snapshots) != 1 || list.Snapshots[0].ID != snap.ID || list.TotalCount == nil || *list.TotalCount != 1 {
		t.Fatalf("list = %+v", list)
	}
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?metadata[stage][in]=prod,qa", nil, &list), http.StatusOK)
	if len(list.Snapshots) != 0 {
		t.Fatalf("metadata[in] filter = %+v", list)
	}

	var updated snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID, `{"metadata":{"stage":"prod"}}`, &updated), http.StatusOK)
	if updated.Metadata["stage"] != "prod" || updated.Name == nil || *updated.Name != "base" {
		t.Fatalf("update = %+v", updated)
	}

	// A devbox created from the snapshot records it.
	from := env.mustCreate(t, `{"snapshot_id":"`+snap.ID+`"}`)
	if from.SnapshotID == nil || *from.SnapshotID != snap.ID {
		t.Fatalf("devbox from snapshot = %+v", from)
	}

	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", nil, nil), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, nil), http.StatusNotFound)
	// Deleting again is a no-op success.
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID+"/delete", nil, nil), http.StatusOK)
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+snap.ID, `{}`, nil), http.StatusNotFound)
}

func TestSnapshotDiskAsyncAndFailure(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	var snap snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk_async", `{}`, &snap), http.StatusOK)
	var status snapshotStatusView
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+snap.ID+"/status", nil, &status), http.StatusOK)
	if status.Status != "complete" {
		t.Fatalf("async status = %+v", status)
	}

	env.runtime.errSnapshot = errors.New("commit failed")
	old := snapshotHold
	snapshotHold = time.Second
	t.Cleanup(func() { snapshotHold = old })
	rr := env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk_async", `{"name":"broken"}`, nil, "X-Request-Id", "snap-fail")
	if rr.Code < 400 {
		t.Fatalf("failed snapshot status = %d", rr.Code)
	}
	// The failure stays answerable on the status route.
	id := snapshotPrefix + devbox.ID + "." + shortHash("", "snap-fail", `{"name":"broken"}`)
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+id+"/status", nil, &status), http.StatusOK)
	if status.Status != "error" || status.ErrorMessage == nil {
		t.Fatalf("failed status = %+v", status)
	}
	expectStatus(t, env.do(t, http.MethodPost, "/sb-missing/snapshot_disk", `{}`, nil), http.StatusNotFound)
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/snapshot_disk", `{`, nil), http.StatusBadRequest)
}

func TestNativeSnapshotsAreAddressable(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	// A snapshot taken outside the facade.
	native, _, err := env.svc.CreateSnapshotWithOwnership(context.Background(), devbox.ID, models.CreateSandboxSnapshotRequest{Name: "team/base:v1"})
	if err != nil {
		t.Fatalf("CreateSnapshotWithOwnership: %v", err)
	}
	var list listSnapshotsResponse
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?limit=1", nil, &list), http.StatusOK)
	if len(list.Snapshots) != 1 || list.Snapshots[0].ID != snapshotIDForName(native.Name) {
		t.Fatalf("native listing = %+v", list)
	}
	id := list.Snapshots[0].ID
	var status snapshotStatusView
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/"+id+"/status", nil, &status), http.StatusOK)
	var updated snapshotView
	expectStatus(t, env.do(t, http.MethodPost, "/disk_snapshots/"+id, `{"name":"renamed"}`, &updated), http.StatusOK)
	if updated.ID != id || updated.Name == nil || *updated.Name != "renamed" {
		t.Fatalf("native update = %+v", updated)
	}
	env.mustCreate(t, `{"snapshot_id":"`+id+`"}`)
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/snx-!!/status", nil, nil), http.StatusNotFound)
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots/snp-unknown/status", nil, nil), http.StatusNotFound)
	expectStatus(t, env.do(t, http.MethodGet, "/disk_snapshots?limit=x", nil, nil), http.StatusBadRequest)
}

func TestSnapshotHelpers(t *testing.T) {
	if id, ok := snapshotSourceDevbox("snp-sb-0123.89ab"); !ok || id != "sb-0123" {
		t.Fatalf("source = %q %v", id, ok)
	}
	for _, bad := range []string{"snp-sb-0123", "snx-abc", "snp-sb/x.89ab", "snp-sb-0123.zz"} {
		if _, ok := snapshotSourceDevbox(bad); ok {
			t.Fatalf("snapshotSourceDevbox(%q) accepted", bad)
		}
	}
	filters := metadataQuery(map[string][]string{"metadata[a]": {"1"}, "metadata[b][in]": {"x,y"}, "limit": {"3"}})
	if !metadataMatches(map[string]string{"a": "1", "b": "y"}, filters) || metadataMatches(map[string]string{"a": "1"}, filters) || metadataMatches(map[string]string{"a": "2", "b": "x"}, filters) {
		t.Fatal("metadata filter mismatch")
	}
}
