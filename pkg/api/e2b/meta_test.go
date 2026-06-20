package e2b

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// UC-19/UC-20: volume mounts attached at create round-trip through the sealed
// compat blob, so GET/list can echo them (name+path only) after a restart.
func TestVolumeMountsRoundTripThroughCompatBlob(t *testing.T) {
	in := sandboxMeta{
		TemplateID: "base",
		Secure:     true,
		OnTimeout:  "kill",
		VolumeMounts: []sandboxVolumeMountPayload{
			{Name: "data", Path: "/workspace"},
			{Name: "cache", Path: "/cache"},
		},
	}
	encoded, err := sandboxMetaToState(in)
	if err != nil {
		t.Fatalf("sandboxMetaToState: %v", err)
	}
	if !strings.Contains(encoded, "volume_mounts") {
		t.Fatalf("blob missing volume_mounts: %s", encoded)
	}
	out, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: encoded}, nil)
	if err != nil {
		t.Fatalf("sandboxMetaFromState: %v", err)
	}
	if len(out.VolumeMounts) != 2 {
		t.Fatalf("round-trip volume mounts = %d, want 2", len(out.VolumeMounts))
	}
	if out.VolumeMounts[0].Name != "data" || out.VolumeMounts[0].Path != "/workspace" {
		t.Fatalf("round-trip = %+v", out.VolumeMounts)
	}
}

// A blob with no volume mounts yields a non-nil empty slice (response builders
// index into it).
func TestVolumeMountsEmptyIsNonNil(t *testing.T) {
	out := cloneVolumeMounts(nil)
	if out == nil || len(out) != 0 {
		t.Fatalf("cloneVolumeMounts(nil) = %v, want non-nil empty", out)
	}
	// Entries missing name or path are dropped.
	dropped := cloneVolumeMounts([]sandboxVolumeMountPayload{{Name: "x"}, {Path: "/y"}, {Name: "ok", Path: "/ok"}})
	if len(dropped) != 1 {
		t.Fatalf("expected 1 valid entry, got %d", len(dropped))
	}
}

func TestServerlessFromMetadata(t *testing.T) {
	cases := []struct {
		m    map[string]string
		want bool
	}{
		{nil, false},
		{map[string]string{}, false},
		{map[string]string{metadataKeyServerless: "true"}, true},
		{map[string]string{metadataKeyServerless: "1"}, true},
		{map[string]string{metadataKeyServerless: "yes"}, true},
		{map[string]string{metadataKeyServerless: "on"}, true},
		{map[string]string{metadataKeyServerless: "FALSE"}, false},
		{map[string]string{metadataKeyServerless: "  TRUE  "}, true},
	}
	for _, tc := range cases {
		if got := serverlessFromMetadata(tc.m); got != tc.want {
			t.Errorf("serverlessFromMetadata(%v) = %v, want %v", tc.m, got, tc.want)
		}
	}
}

func TestSandboxMetaFromNative(t *testing.T) {
	blob := compatBlob{
		TemplateID:      "tid",
		NetworkAllowOut: []string{"a"},
	}

	t.Run("nil sandbox", func(t *testing.T) {
		meta := sandboxMetaFromNative(nil, blob)
		if meta.TemplateID != "tid" {
			t.Errorf("want tid, got %s", meta.TemplateID)
		}
	})

	t.Run("with sandbox", func(t *testing.T) {
		sb := &models.Sandbox{
			Image:           "img",
			Tags:            map[string]string{"k": "v"},
			NetworkBlockAll: false,
			Lifecycle:       models.Lifecycle{StopAtAge: time.Hour},
			CreatedAt:       time.Now(),
		}
		meta := sandboxMetaFromNative(sb, blob)
		if meta.TemplateID != "tid" {
			t.Errorf("want tid, got %s", meta.TemplateID)
		}
		if *meta.AllowInternetAccess != true {
			t.Errorf("want true")
		}
		if meta.TimeoutSeconds <= 0 {
			t.Errorf("expected timeout > 0")
		}
	})
}

func TestSandboxMetaFromState(t *testing.T) {
	t.Run("nil state", func(t *testing.T) {
		meta, err := sandboxMetaFromState(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if meta.Secure != true || meta.OnTimeout != "kill" {
			t.Error("unexpected default")
		}
	})

	t.Run("empty json", func(t *testing.T) {
		meta, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: "  "}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if meta.Secure != true || meta.OnTimeout != "kill" {
			t.Error("unexpected default")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: "{"}, nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("valid state", func(t *testing.T) {
		blob := `{"template_id":"tid","auto_resume":true}`
		meta, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: blob}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if meta.TemplateID != "tid" || meta.AutoResume != true {
			t.Error("unexpected meta parsing")
		}
	})
}

func TestSandboxMetaToState(t *testing.T) {
	meta := sandboxMeta{
		TemplateID: "tid",
		AutoResume: true,
	}
	s, err := sandboxMetaToState(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, `"template_id":"tid"`) || !strings.Contains(s, `"auto_resume":true`) {
		t.Error("unexpected marshal", s)
	}
}

func TestDeriveTimeoutConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		d, a := deriveTimeoutConfig(nil)
		if d != 0 || a != "kill" {
			t.Errorf("want 0, kill; got %d, %s", d, a)
		}
	})

	now := time.Now()
	t.Run("stop at age", func(t *testing.T) {
		sb := &models.Sandbox{
			CreatedAt: now,
			Lifecycle: models.Lifecycle{StopAtAge: 2 * time.Second},
		}
		d, a := deriveTimeoutConfig(sb)
		if d <= 0 || a != "pause" {
			t.Errorf("want >0, pause; got %d, %s", d, a)
		}
	})

	t.Run("stop at age expired", func(t *testing.T) {
		sb := &models.Sandbox{
			CreatedAt: now.Add(-5 * time.Second),
			Lifecycle: models.Lifecycle{StopAtAge: 2 * time.Second},
		}
		d, a := deriveTimeoutConfig(sb)
		if d != 0 || a != "pause" {
			t.Errorf("want 0, pause; got %d, %s", d, a)
		}
	})

	t.Run("destroy at age", func(t *testing.T) {
		sb := &models.Sandbox{
			CreatedAt: now,
			Lifecycle: models.Lifecycle{DestroyAtAge: 2 * time.Second},
		}
		d, a := deriveTimeoutConfig(sb)
		if d <= 0 || a != "kill" {
			t.Errorf("want >0, kill; got %d, %s", d, a)
		}
	})
}

func TestSnapshotIDFromName(t *testing.T) {
	if got := snapshotIDFromName(""); got != "" {
		t.Error("expected empty")
	}
	name := "my-snap:default"
	got := snapshotIDFromName(name)
	if !strings.HasPrefix(got, "snapshot_") {
		t.Error("missing prefix")
	}
}

func TestMetaSnapshotNameFromID(t *testing.T) {
	t.Run("invalid prefix", func(t *testing.T) {
		_, ok := snapshotNameFromID("foo")
		if ok {
			t.Error("expected false")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, ok := snapshotNameFromID("snapshot_!!!")
		if ok {
			t.Error("expected false")
		}
	})

	t.Run("empty name decoded", func(t *testing.T) {
		_, ok := snapshotNameFromID("snapshot_")
		if ok {
			t.Error("expected false")
		}
	})

	t.Run("valid", func(t *testing.T) {
		id := "snapshot_" + base64.RawURLEncoding.EncodeToString([]byte("foo:default"))
		name, ok := snapshotNameFromID(id)
		if !ok || name != "foo:default" {
			t.Errorf("want foo:default, true; got %s, %v", name, ok)
		}
	})
}

func TestCreateRequestFingerprint(t *testing.T) {
	f, err := createRequestFingerprint("tid", models.CreateSandboxRequest{NetworkBlockAll: true}, sandboxMeta{TimeoutSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f, "fingerprint:") {
		t.Error("missing prefix", f)
	}
}
