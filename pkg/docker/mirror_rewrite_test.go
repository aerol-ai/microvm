package docker

import (
	"testing"
)

func defaultMirrorCfg() MirrorConfig {
	return MirrorConfig{
		Host:     "mirror.aocr.aerol.ai",
		PushHost: "aocr.aerol.ai",
		Upstreams: []MirrorUpstream{
			{Host: "ghcr.io", Shortname: "ghcr"},
			{Host: "gcr.io", Shortname: "gcr"},
			{Host: "quay.io", Shortname: "quay"},
			{Host: "registry.k8s.io", Shortname: "k8s"},
		},
	}
}

func TestRewriteImageRefForMirror_DisabledConfig(t *testing.T) {
	for name, cfg := range map[string]MirrorConfig{
		"zero":         {},
		"no-host":      {Upstreams: []MirrorUpstream{{Host: "ghcr.io", Shortname: "ghcr"}}},
		"no-upstreams": {Host: "mirror.aocr.aerol.ai"},
	} {
		t.Run(name, func(t *testing.T) {
			r := RewriteImageRefForMirror("ghcr.io/aerol-ai/sandbox:v1", cfg)
			if r.Rewritten {
				t.Fatalf("disabled cfg should never rewrite (case %s): got %+v", name, r)
			}
			if r.RewrittenRef != "ghcr.io/aerol-ai/sandbox:v1" {
				t.Fatalf("ref must pass through unchanged: %s", r.RewrittenRef)
			}
		})
	}
}

func TestRewriteImageRefForMirror_EmptyAndWhitespace(t *testing.T) {
	cfg := defaultMirrorCfg()
	for _, ref := range []string{"", "   ", "\n"} {
		r := RewriteImageRefForMirror(ref, cfg)
		if r.Rewritten {
			t.Fatalf("empty input must not rewrite, got %+v", r)
		}
	}
}

func TestRewriteImageRefForMirror_GHCRWithTag(t *testing.T) {
	r := RewriteImageRefForMirror("ghcr.io/aerol-ai/sandbox:v1.2.3", defaultMirrorCfg())
	if !r.Rewritten {
		t.Fatalf("expected rewrite, got %+v", r)
	}
	if r.RewrittenRef != "mirror.aocr.aerol.ai/aocr/ghcr/aerol-ai/sandbox:v1.2.3" {
		t.Fatalf("unexpected rewritten ref: %s", r.RewrittenRef)
	}
	if r.OriginalRef != "ghcr.io/aerol-ai/sandbox:v1.2.3" {
		t.Fatalf("original ref lost: %s", r.OriginalRef)
	}
	if r.UpstreamHost != "ghcr.io" {
		t.Fatalf("UpstreamHost: %s", r.UpstreamHost)
	}
	if r.UpstreamRepo != "aocr/ghcr/aerol-ai/sandbox" {
		t.Fatalf("UpstreamRepo: %s", r.UpstreamRepo)
	}
	if r.UpstreamTag != "v1.2.3" {
		t.Fatalf("UpstreamTag: %s", r.UpstreamTag)
	}
}

func TestRewriteImageRefForMirror_DigestRef(t *testing.T) {
	digest := "sha256:aabbccdd"
	r := RewriteImageRefForMirror("gcr.io/distroless/base@"+digest, defaultMirrorCfg())
	if !r.Rewritten {
		t.Fatalf("expected rewrite, got %+v", r)
	}
	want := "mirror.aocr.aerol.ai/aocr/gcr/distroless/base@" + digest
	if r.RewrittenRef != want {
		t.Fatalf("rewritten ref: got %s want %s", r.RewrittenRef, want)
	}
	if r.UpstreamTag != "" {
		t.Fatalf("digest pull should have no tag, got %q", r.UpstreamTag)
	}
}

func TestRewriteImageRefForMirror_NoTag(t *testing.T) {
	r := RewriteImageRefForMirror("quay.io/prometheus/node-exporter", defaultMirrorCfg())
	if !r.Rewritten {
		t.Fatalf("expected rewrite, got %+v", r)
	}
	if r.RewrittenRef != "mirror.aocr.aerol.ai/aocr/quay/prometheus/node-exporter" {
		t.Fatalf("rewritten ref: %s", r.RewrittenRef)
	}
	if r.UpstreamTag != "" {
		t.Fatalf("UpstreamTag should be empty, got %q", r.UpstreamTag)
	}
}

func TestRewriteImageRefForMirror_K8sSingleSegment(t *testing.T) {
	// registry.k8s.io/pause:3.9 — one path segment after the host. Common
	// shape and a regression target since some splitters assume org/repo.
	r := RewriteImageRefForMirror("registry.k8s.io/pause:3.9", defaultMirrorCfg())
	if !r.Rewritten {
		t.Fatalf("expected rewrite, got %+v", r)
	}
	if r.RewrittenRef != "mirror.aocr.aerol.ai/aocr/k8s/pause:3.9" {
		t.Fatalf("rewritten ref: %s", r.RewrittenRef)
	}
	if r.UpstreamRepo != "aocr/k8s/pause" {
		t.Fatalf("UpstreamRepo: %s", r.UpstreamRepo)
	}
}

func TestRewriteImageRefForMirror_DockerHubPassThrough(t *testing.T) {
	cfg := defaultMirrorCfg()
	for _, ref := range []string{
		"redis",
		"redis:7.2",
		"library/redis",
		"library/redis:7.2",
		"grafana/grafana:11",
		"docker.io/library/redis:7.2", // explicit docker.io still passes through
	} {
		r := RewriteImageRefForMirror(ref, cfg)
		if r.Rewritten {
			t.Fatalf("docker.io ref %q must not be rewritten (daemon.json mirror handles it), got %+v", ref, r)
		}
		if r.RewrittenRef != ref {
			t.Fatalf("ref %q changed to %q", ref, r.RewrittenRef)
		}
	}
}

func TestRewriteImageRefForMirror_UnknownHostPassesThrough(t *testing.T) {
	cfg := defaultMirrorCfg()
	for _, ref := range []string{
		"my-private-registry.corp.example.com/team/app:v1",
		"123.dkr.ecr.us-east-1.amazonaws.com/team/app:v1",
		"localhost:5000/dev/app:latest",
	} {
		r := RewriteImageRefForMirror(ref, cfg)
		if r.Rewritten {
			t.Fatalf("unknown host %q must pass through, got %+v", ref, r)
		}
	}
}

func TestRewriteImageRefForMirror_IdempotentOnAlreadyRewritten(t *testing.T) {
	cfg := defaultMirrorCfg()
	ref := "mirror.aocr.aerol.ai/aocr/ghcr/aerol-ai/sandbox:v1"
	r := RewriteImageRefForMirror(ref, cfg)
	if r.Rewritten {
		t.Fatalf("already-rewritten ref must pass through, got %+v", r)
	}
	if r.RewrittenRef != ref {
		t.Fatalf("ref mutated: %s", r.RewrittenRef)
	}
}

func TestRewriteImageRefForMirror_PushVhostPassesThrough(t *testing.T) {
	cfg := defaultMirrorCfg()
	// Cluster-snapshot refs live under the push vhost — never rewrite them.
	ref := "aocr.aerol.ai/cluster/abc/snap:foo"
	r := RewriteImageRefForMirror(ref, cfg)
	if r.Rewritten {
		t.Fatalf("push-vhost ref must pass through, got %+v", r)
	}
}

func TestRewriteImageRefForMirror_HostCaseInsensitive(t *testing.T) {
	r := RewriteImageRefForMirror("GHCR.IO/Aerol-AI/Sandbox:V1", defaultMirrorCfg())
	if !r.Rewritten {
		t.Fatalf("uppercase host should still match, got %+v", r)
	}
	// Host gets lowercased but repo + tag are preserved verbatim.
	if r.RewrittenRef != "mirror.aocr.aerol.ai/aocr/ghcr/Aerol-AI/Sandbox:V1" {
		t.Fatalf("rewritten ref: %s", r.RewrittenRef)
	}
}

func TestSplitHostRepo(t *testing.T) {
	cases := []struct{ in, host, repo string }{
		{"redis", "", "redis"},
		{"library/redis", "", "library/redis"},
		{"ghcr.io/foo/bar", "ghcr.io", "foo/bar"},
		{"localhost:5000/foo", "localhost:5000", "foo"},
		{"localhost/foo", "localhost", "foo"},
		{"registry.k8s.io/pause", "registry.k8s.io", "pause"},
	}
	for _, c := range cases {
		h, r := splitHostRepo(c.in)
		if h != c.host || r != c.repo {
			t.Fatalf("splitHostRepo(%q) = (%q,%q) want (%q,%q)", c.in, h, r, c.host, c.repo)
		}
	}
}

func TestSplitRepoRefTag(t *testing.T) {
	cases := []struct{ in, repo, tag, digest string }{
		{"foo/bar", "foo/bar", "", ""},
		{"foo/bar:1.2", "foo/bar", "1.2", ""},
		{"foo/bar@sha256:abc", "foo/bar", "", "sha256:abc"},
		{"foo/bar:1.2@sha256:abc", "foo/bar", "1.2", "sha256:abc"},
		{"pause:3.9", "pause", "3.9", ""},
	}
	for _, c := range cases {
		r, tg, d := splitRepoRefTag(c.in)
		if r != c.repo || tg != c.tag || d != c.digest {
			t.Fatalf("splitRepoRefTag(%q) = (%q,%q,%q) want (%q,%q,%q)", c.in, r, tg, d, c.repo, c.tag, c.digest)
		}
	}
}
