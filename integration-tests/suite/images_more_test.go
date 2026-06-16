//go:build integration

package suite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// UC-76 — The fluent Dockerfile builder emits every directive it supports and
// the daemon builds the result. UC-46 only exercised BaseImage+RunCommands;
// this covers Env/Workdir/Entrypoint/Cmd/User/Expose in one graph. The compiled
// Dockerfile is asserted directive-by-directive (deterministic, offline) and
// then handed to the daemon to prove it accepts the multi-directive build.
func TestRichImageBuilder(t *testing.T) {
	harness.Require(t, sc, "UC-76")
	c := client(t)

	img := microvm.BaseImage("alpine:3.20").
		Env(map[string]string{"UC76": "value-76"}).
		Workdir("/opt/app").
		RunCommands("echo rich-builder-76 > /opt/app/uc76.txt").
		Expose(8080).
		User("root").
		Entrypoint("/bin/sh", "-c").
		Cmd("sleep", "300")
	if err := img.Err(); err != nil {
		t.Fatalf("rich image spec: %v", err)
	}

	// Each builder method must have emitted its directive.
	df := img.Dockerfile()
	for _, want := range []string{
		"FROM alpine:3.20",
		"ENV UC76=value-76",
		"WORKDIR /opt/app",
		"RUN echo rich-builder-76",
		"EXPOSE 8080",
		"USER root",
		"ENTRYPOINT [",
		"CMD [",
	} {
		if !strings.Contains(df, want) {
			t.Fatalf("compiled Dockerfile missing %q:\n%s", want, df)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	tag, err := c.SDK().BuildImage(ctx, img)
	if err != nil {
		t.Fatalf("build rich image: %v", err)
	}
	if tag == "" {
		t.Fatal("build returned empty image tag")
	}
}
