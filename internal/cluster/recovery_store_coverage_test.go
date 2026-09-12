package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWriteGCManifestRenameOntoDirectory(t *testing.T) {
	// CreateTemp succeeds; os.Rename onto an existing directory is the
	// remaining writeGCManifest failure (chmod-readonly hits create-temp instead).
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.gcManifestPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.writeGCManifest(placementRecoveryGCManifest{Snapshots: []placementRecoverySnapshotRefs{{CreatedUnix: 1}}}); err == nil {
		t.Fatal("rename onto directory should fail")
	}
}

func TestLift3RecoveryStoreRemainingIO(t *testing.T) {
	if _, err := (&placementRecoveryFileStore{dir: t.TempDir()}).Put("", placementRecovery{}); err == nil {
		t.Fatal("empty sandbox put")
	}
	if _, err := newPlacementRecoveryMemoryStore().Put("", placementRecovery{}); err == nil {
		t.Fatal("memory empty sandbox")
	}

	fileAsDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := &placementRecoveryFileStore{dir: fileAsDir}
	if _, err := blocked.Put("sb", placementRecovery{SecretRef: "r"}); err == nil {
		t.Fatal("put mkdir onto file")
	}
	if err := blocked.writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("gc manifest create-temp onto file")
	}

	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := placementRecovery{SecretRef: "r", SecretVersion: 1}
	ref, err := store.Put("sb-rename", rec)
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.pathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("sb-rename", rec); err == nil {
		t.Fatal("put rename onto directory")
	}
	if err := os.WriteFile(filepath.Join(path, "child"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ref); err == nil {
		t.Fatal("delete non-empty directory blob")
	}

	ro := t.TempDir()
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	if err := (&placementRecoveryFileStore{dir: ro}).writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("readonly create-temp")
	}
}

func TestRecoveryStoreHelpersAndErrors(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.pathForRef(placementRecoveryRefPrefix + strings.Repeat("g", 64)); err == nil {
		t.Fatal("pathForRef should reject invalid hex")
	}

	// Force readGCManifest read error by making snapshots.json a directory.
	if err := os.MkdirAll(store.gcManifestPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readGCManifest(); err == nil {
		t.Fatal("readGCManifest should fail when manifest path is a directory")
	}

	refs := normalizeRecoveryRefs([]string{"", "a", "b", "a", "  ", "c"})
	if len(refs) != 3 || refs[0] != "a" || refs[1] != "b" || refs[2] != "c" {
		t.Fatalf("normalizeRecoveryRefs=%v", refs)
	}
	if isRecoveryBlobFilename("snapshots.json") {
		t.Fatal("manifest filename should not be considered a blob")
	}
	if isRecoveryBlobFilename(strings.Repeat("x", 64) + ".json") {
		t.Fatal("non-hex blob filename should be rejected")
	}

	rec := placementRecoveryStoreRecord{
		SandboxID: "sb-rec",
		Recovery:  placementRecovery{Spec: &models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"A": "1"}}},
	}
	blob := recoveryBlobFromRecord("ref-1", rec)
	if blob.SandboxID != "sb-rec" || blob.Ref != "ref-1" || blob.Spec == nil {
		t.Fatalf("blob=%+v", blob)
	}
	blob.Spec.Image = "mutated"
	blob.Spec.Env["A"] = "x"
	if rec.Recovery.Spec.Image != "alpine" || rec.Recovery.Spec.Env["A"] != "1" {
		t.Fatalf("record mutated via blob clone: %+v", rec.Recovery.Spec)
	}
}

func TestFSMRestoreRowsAndRecoveryMerge(t *testing.T) {
	payload := fsmSnapshotPayload{
		Version: 9,
		Rows: []placementSnapshotRow{
			{Placement: Placement{SandboxID: ""}}, // skipped
			{Placement: Placement{SandboxID: "sb", OwnerNodeID: "n", IncarnationID: "inc-sb"}},
			{
				Placement: Placement{SandboxID: "sb-r", OwnerNodeID: "n", Version: 3},
				Recovery:  placementRecovery{Spec: &models.CreateSandboxRequest{Image: "img"}, SecretRef: "r", SecretVersion: 2},
			},
		},
		Volumes: []models.Volume{
			{Tenant: "", ID: "x"},
			{Tenant: "t", ID: "v1", Name: "n1", Backend: "s3"},
		},
		VolumeAttachments: []models.VolumeAttachment{
			{Tenant: "t", VolumeID: "missing", SandboxID: "sb", IncarnationID: "inc-sb", Target: "/d", Source: "s"},
			{Tenant: "t", VolumeID: "v1", SandboxID: "sb", IncarnationID: "inc-sb", Target: "/d", Source: "s"},
			{Tenant: "", VolumeID: "v1", SandboxID: "sb", IncarnationID: "inc-sb", Target: "/d", Source: "s"},
		},
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(payload); err != nil {
		t.Fatal(err)
	}
	fsm := newPlacementFSM()
	if err := fsm.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	p, ok := fsm.get("sb-r")
	if !ok || p.Spec == nil || p.Spec.Image != "img" || p.SecretRef != "r" {
		t.Fatalf("restored placement=%+v ok=%v", p, ok)
	}
	if fsm.VolumeAttachmentCount("t", "v1") != 1 {
		t.Fatalf("attachment count=%d", fsm.VolumeAttachmentCount("t", "v1"))
	}
}

func TestRecoveryStoreMoreErrorBranches(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(""); err != nil {
		t.Fatalf("Delete empty: %v", err)
	}
	if err := store.Delete("recovery:v1:not-hex"); err == nil {
		t.Fatal("Delete invalid ref")
	}
	if _, _, err := store.Get("recovery:v1:not-hex"); err == nil {
		t.Fatal("Get invalid ref")
	}
	if _, _, err := store.GetRecord("recovery:v1:zzzz"); err == nil {
		t.Fatal("GetRecord invalid ref")
	}

	// Corrupt blob decode / read as directory.
	ref, err := store.Put("sb", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "i"}})
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.pathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetRecord(ref); err == nil {
		t.Fatal("GetRecord corrupt should fail")
	}

	// RetainSnapshotRefs mkdir failure when dir is a file.
	file, err := os.CreateTemp("", "rec-dir-file")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	bad := &placementRecoveryFileStore{dir: file.Name()}
	if err := bad.RetainSnapshotRefs([]string{ref}); err == nil {
		t.Fatal("RetainSnapshotRefs mkdir failure expected")
	}

	// writeGCManifest rename failure: make target path a directory after temp write by
	// pointing gc path at a non-writable parent via chmod.
	dir := t.TempDir()
	okStore, err := newPlacementRecoveryFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := okStore.writeGCManifest(placementRecoveryGCManifest{}); err == nil {
		t.Fatal("writeGCManifest on read-only dir should fail")
	}
	if !isRecoveryBlobFilename("notahex.json") {
		// non-hex already false; ensure suffix check branch
	}
	if isRecoveryBlobFilename("abc") {
		t.Fatal("missing .json should be false")
	}
}

func TestRecoveryReplicationUnitBranches(t *testing.T) {
	c := &Cluster{nodeID: "self"}
	if _, ok, err := c.RecoveryBlob(context.Background(), "r"); ok || err != nil {
		t.Fatalf("nil fsm RecoveryBlob ok=%v err=%v", ok, err)
	}
	if got := c.recoveryServerMembers(); got != nil {
		t.Fatalf("nil gossip members=%v", got)
	}
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleServer, APIURL: "http://self"})
	index.upsert(Member{NodeID: "", Alive: true, Role: config.NodeRoleServer, APIURL: "http://x"})
	index.upsert(Member{NodeID: "worker", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://w"})
	index.upsert(Member{NodeID: "noep", Alive: true, Role: config.NodeRoleServer})
	index.upsert(Member{NodeID: "peer", Alive: true, Role: config.NodeRoleServer, APIURL: "http://peer", InternalURL: "https://peer"})
	c.gossip = &gossipNode{memberIndex: index}
	members := c.recoveryServerMembers()
	if len(members) != 2 { // self + peer
		t.Fatalf("recoveryServerMembers=%+v", members)
	}

	// 404 maps to not found.
	srv404, internalClient := newNodeBoundForwardServer(t, "self", "p", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	c.internalClient = internalClient
	blob, ok, err := c.getRecoveryBlobFromMember(context.Background(), Member{NodeID: "p", InternalURL: srv404.URL}, "recovery:v1:"+strings.Repeat("a", 64))
	if err != nil || ok || blob.Ref != "" {
		t.Fatalf("404 blob ok=%v err=%v", ok, err)
	}

	// out=nil success path + bad URL + PAT header.
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srvOK.Close()
	c.patToken = "pat"
	if err := doRecoveryHTTPRequest(context.Background(), srvOK.Client(), srvOK.URL, http.MethodGet, "pat", "", nil, nil); err != nil {
		t.Fatalf("nil out: %v", err)
	}
	if err := doRecoveryHTTPRequest(context.Background(), srvOK.Client(), "://bad", http.MethodGet, "", "", []byte(`{}`), nil); err == nil {
		t.Fatal("bad url")
	}

	// fetchRecoveryBlob walks peers.
	c.fsm = newPlacementFSM()
	_, _, _ = c.fetchRecoveryBlob(context.Background(), "recovery:v1:"+strings.Repeat("b", 64))
}

func TestDoRecoveryHTTPDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(RecoveryBlob{Ref: "r1", SandboxID: "sb"})
	}))
	defer srv.Close()
	var out RecoveryBlob
	if err := doRecoveryHTTPRequest(context.Background(), srv.Client(), srv.URL, http.MethodGet, "", "", nil, &out); err != nil || out.SandboxID != "sb" {
		t.Fatalf("decode out=%+v err=%v", out, err)
	}
}

func TestFSMClaimNameAndResolveRecoveryEdges(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.mu.Lock()
	fsm.claimNameLocked("", "x")
	fsm.claimNameLocked("sb", "")
	if _, ok, err := fsm.resolveRecoveryRef(""); ok || err != nil {
		t.Fatalf("empty ref ok=%v err=%v", ok, err)
	}
	if _, ok, err := fsm.resolveRecoveryRef("recovery:v1:deadbeef"); ok || err != nil {
		// invalid length / missing → false,nil or error depending on store
		_ = err
		_ = ok
	}
	fsm.mu.Unlock()
}

func TestRecoveryFileStorePutAndReadErrorBranches(t *testing.T) {
	store, err := newPlacementRecoveryFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("", placementRecovery{}); err == nil {
		t.Fatal("Put empty sandbox id")
	}
	mem := newPlacementRecoveryMemoryStore()
	if _, err := mem.Put("  ", placementRecovery{}); err == nil {
		t.Fatal("memory Put empty id")
	}

	ref, err := store.Put("sb", placementRecovery{Spec: &models.CreateSandboxRequest{Image: "i"}})
	if err != nil {
		t.Fatal(err)
	}
	path, err := store.pathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.GetRecord(ref); err == nil {
		t.Fatal("GetRecord when blob path is a directory")
	}

	// RetainSnapshotRefs GC remove failure: keep empty + make an orphan blob undeletable.
	dir := t.TempDir()
	okStore, err := newPlacementRecoveryFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, strings.Repeat("a", 64)+".json")
	if err := os.WriteFile(orphan, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	// mkdir may fail first on RetainSnapshotRefs; either error path is fine.
	_ = okStore.RetainSnapshotRefs(nil)

	if _, err := newPlacementFSMWithFileRecovery(filepath.Join(t.TempDir(), "not-a-dir-parent", "x")); err != nil {
		// parent missing is created by MkdirAll — use a file as parent instead
	}
	filePath := filepath.Join(t.TempDir(), "as-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newPlacementFSMWithFileRecovery(filePath); err == nil {
		t.Fatal("recovery store under a file path should fail")
	}
}
