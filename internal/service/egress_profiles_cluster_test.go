package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// profileCluster is an in-memory replicated profile store.
type profileCluster struct {
	*cluster.Noop
	profiles map[cluster.EgressProfileKey]cluster.EgressProfileRecord
	writeErr error
	readErr  error
}

func newProfileCluster() *profileCluster {
	return &profileCluster{Noop: cluster.NewNoop("self", "http://self", ""), profiles: map[cluster.EgressProfileKey]cluster.EgressProfileRecord{}}
}

func (c *profileCluster) WriteEgressProfile(_ context.Context, req cluster.EgressProfileWriteRequest) (cluster.EgressProfileWriteResponse, error) {
	if c.writeErr != nil {
		return cluster.EgressProfileWriteResponse{}, c.writeErr
	}
	k := cluster.EgressProfileKey{Owner: req.Profile.Owner, Name: req.Profile.Name}
	if req.Delete {
		delete(c.profiles, k)
		return cluster.EgressProfileWriteResponse{}, nil
	}
	p := req.Profile
	p.Generation = c.profiles[k].Generation + 1
	p.CreatedUnixNano, p.UpdatedUnixNano = 1, 2
	c.profiles[k] = p
	return cluster.EgressProfileWriteResponse{Profile: p, Changed: true}, nil
}

func (c *profileCluster) ReadEgressProfiles(_ context.Context, req cluster.EgressProfileReadRequest) (cluster.EgressProfileReadResponse, error) {
	if c.readErr != nil {
		return cluster.EgressProfileReadResponse{}, c.readErr
	}
	out := cluster.EgressProfileReadResponse{Authoritative: true}
	for k, p := range c.profiles {
		if k.Owner != req.Owner {
			continue
		}
		if len(req.Names) == 0 || slices.Contains(req.Names, k.Name) {
			out.Profiles = append(out.Profiles, p)
		}
	}
	return out, nil
}

func TestClusterEgressProfileBackend(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	pc := newProfileCluster()
	svc.AttachCluster(pc)
	svc.cfg.EnableCluster = true
	ctx := ownerCtx("acct")
	p, err := svc.PutEgressProfile(ctx, "python", models.EgressProfileRequest{AllowOut: []string{"pypi.org"}, Description: "pip"})
	if err != nil || p.Generation != 1 || p.Description != "pip" || p.CreatedAt.IsZero() {
		t.Fatalf("put = %+v %v", p, err)
	}
	if rec := pc.profiles[cluster.EgressProfileKey{Owner: "acct", Name: "python"}]; rec.HostnameCount != 1 {
		t.Fatalf("the proposer sends the hostname count: %+v", rec)
	}
	if got, err := svc.GetEgressProfile(ctx, "python"); err != nil || got.Generation != 1 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := svc.GetEgressProfile(ctx, "missing"); !errors.Is(err, ErrEgressProfileNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if page, err := svc.ListEgressProfiles(ctx, "", 0); err != nil || len(page.Profiles) != 1 {
		t.Fatalf("list = %+v %v", page, err)
	}
	// A create resolves its profile through the replicated store.
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"python"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(gw.attached["sb-pol"].AllowOut, "pypi.org") {
		t.Fatalf("gateway = %+v", gw.attached["sb-pol"])
	}

	for _, tc := range []struct {
		err  error
		want error
	}{
		{cluster.ErrEgressProfileInUse, ErrEgressProfileInUse},
		{cluster.ErrEgressProfileCapExceeded, ErrEgressProfileCapExceeded},
		{cluster.ErrClusterVersion, ErrEgressProfileUnavailable},
		{cluster.ErrNotLeader, ErrEgressProfileUnavailable},
	} {
		pc.writeErr = tc.err
		if err := svc.DeleteEgressProfile(ctx, "python"); !errors.Is(err, tc.want) {
			t.Fatalf("delete with %v = %v", tc.err, err)
		}
		if _, err := svc.PutEgressProfile(ctx, "python", models.EgressProfileRequest{AllowOut: []string{"x.example.com"}}); !errors.Is(err, tc.want) {
			t.Fatalf("put with %v = %v", tc.err, err)
		}
	}
	pc.writeErr = nil
	pc.readErr = errors.New("server tier unreachable")
	if _, err := svc.GetEgressProfile(ctx, "python"); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("get when unreachable = %v", err)
	}
	if _, err := svc.ListEgressProfiles(ctx, "", 0); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("list when unreachable = %v", err)
	}
	pc.readErr = nil
	if err := svc.DeleteEgressProfile(ctx, "python"); err != nil {
		t.Fatalf("delete = %v", err)
	}
}
