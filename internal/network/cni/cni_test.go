package cni

import (
	"context"
	"errors"
	"testing"
)

func TestFakeRunnerAddDelIdempotentIP(t *testing.T) {
	f := NewFakeRunner()
	ctx := context.Background()
	r1, err := f.Add(ctx, "/run/netns/a", "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if r1.IP4 == "" {
		t.Fatal("expected ip")
	}
	r2, err := f.Add(ctx, "/run/netns/a", "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if r2.IP4 != r1.IP4 {
		t.Fatalf("second add changed ip: %s -> %s", r1.IP4, r2.IP4)
	}
	if err := f.Del(ctx, "/run/netns/a", "sb-1"); err != nil {
		t.Fatal(err)
	}
	if err := f.Del(ctx, "/run/netns/a", "sb-1"); err != nil {
		t.Fatal("double del should be no-op")
	}
}

func TestFakeRunnerAddError(t *testing.T) {
	f := NewFakeRunner()
	f.SetAddError(errors.New("boom"))
	if _, err := f.Add(context.Background(), "/n", "c"); err == nil {
		t.Fatal("want error")
	}
}

func TestFakeRunnerDelError(t *testing.T) {
	f := NewFakeRunner()
	ctx := context.Background()
	if _, err := f.Add(ctx, "/n", "c"); err != nil {
		t.Fatal(err)
	}
	f.SetDelError(errors.New("boom"))
	if err := f.Del(ctx, "/n", "c"); err == nil {
		t.Fatal("want del error")
	}
}

func TestFakeRunnerRecordsCallOrder(t *testing.T) {
	f := NewFakeRunner()
	ctx := context.Background()
	for i, id := range []string{"a", "b", "c"} {
		if _, err := f.Add(ctx, "/run/"+id, id); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := f.Del(ctx, "/run/"+id, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(f.Adds()) != 3 {
		t.Fatalf("adds = %d", len(f.Adds()))
	}
	if len(f.Dels()) != 2 {
		t.Fatalf("dels = %d", len(f.Dels()))
	}
}

func TestNewExecRunnerValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty plugin dir", Config{ConfPath: "/x"}},
		{"empty conf", Config{PluginDir: "/opt/cni/bin"}},
	}
	for _, tc := range cases {
		if _, err := NewExecRunner(tc.cfg); err == nil {
			t.Fatalf("%s: want error", tc.name)
		}
	}
}

func TestExecRunnerAddRequiresIDs(t *testing.T) {
	r := &ExecRunner{cfg: Config{PluginDir: "/opt/cni/bin", ConfPath: "/etc/cni/net.d/aerolvm.conflist"}}
	if _, err := r.Add(context.Background(), "", "c"); err == nil {
		t.Fatal("want error for empty netns")
	}
	if _, err := r.Add(context.Background(), "/n", ""); err == nil {
		t.Fatal("want error for empty container id")
	}
}

func TestExecRunnerDelEmptyIsNoOp(t *testing.T) {
	r := &ExecRunner{cfg: Config{PluginDir: "/opt/cni/bin", ConfPath: "/etc/cni/net.d/aerolvm.conflist"}}
	if err := r.Del(context.Background(), "", ""); err != nil {
		t.Fatal(err)
	}
}
