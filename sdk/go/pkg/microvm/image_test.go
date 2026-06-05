package microvm

import (
	"strings"
	"testing"
)

func TestImageBuilderCases(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "base_image_emits_from_line",
			run: func(t *testing.T) {
				image := BaseImage("ubuntu:22.04")
				if err := image.Err(); err != nil {
					t.Fatalf("Err() = %v", err)
				}
				if got := image.Dockerfile(); got != "FROM ubuntu:22.04\n" {
					t.Fatalf("Dockerfile() = %q", got)
				}
			},
		},
		{
			name: "run_commands_and_directives_emit_expected_lines",
			run: func(t *testing.T) {
				image := BaseImage("alpine").
					RunCommands("apk add curl", []string{"apk add bash", "echo ready"}).
					Env(map[string]string{"PATH": "/opt/bin:/usr/bin", "FOO": "bar"}).
					Workdir("/app").
					User("nobody").
					Expose(8080).
					Entrypoint("/bin/sh", "-c").
					Cmd("echo", "hi")
				if err := image.Err(); err != nil {
					t.Fatalf("Err() = %v", err)
				}
				want := "FROM alpine\n" +
					"RUN apk add curl\n" +
					"RUN apk add bash && echo ready\n" +
					"ENV FOO=bar PATH=/opt/bin:/usr/bin\n" +
					"WORKDIR /app\n" +
					"USER nobody\n" +
					"EXPOSE 8080\n" +
					"ENTRYPOINT [\"/bin/sh\",\"-c\"]\n" +
					"CMD [\"echo\",\"hi\"]\n"
				if got := image.Dockerfile(); got != want {
					t.Fatalf("Dockerfile() = %q, want %q", got, want)
				}
			},
		},
		{
			name: "from_dockerfile_normalizes_trailing_newline",
			run: func(t *testing.T) {
				image := FromDockerfile("FROM alpine\nRUN echo hi")
				if err := image.Err(); err != nil {
					t.Fatalf("Err() = %v", err)
				}
				if got := image.Dockerfile(); got != "FROM alpine\nRUN echo hi\n" {
					t.Fatalf("Dockerfile() = %q", got)
				}
			},
		},
		{
			name: "invalid_inputs_capture_builder_errors",
			run: func(t *testing.T) {
				cases := []*Image{
					BaseImage("   "),
					FromDockerfile("   "),
					BaseImage("alpine").Workdir(" "),
					BaseImage("alpine").User(" "),
					BaseImage("alpine").Expose(0),
					BaseImage("alpine").Expose(70000),
				}
				for _, image := range cases {
					if err := image.Err(); err == nil {
						t.Fatal("Err() = nil, want error")
					}
				}
			},
		},
		{
			name: "nil_and_error_receivers_are_safe",
			run: func(t *testing.T) {
				var nilImage *Image
				if got := nilImage.Dockerfile(); got != "" {
					t.Fatalf("Dockerfile() = %q, want empty", got)
				}
				if err := nilImage.Err(); err == nil || !strings.Contains(err.Error(), "image is nil") {
					t.Fatalf("Err() = %v, want image is nil", err)
				}
				if got := nilImage.RunCommands("echo hi"); got != nil {
					t.Fatalf("RunCommands() = %+v, want nil", got)
				}
				if got := nilImage.Env(map[string]string{"A": "b"}); got != nil {
					t.Fatalf("Env() = %+v, want nil", got)
				}
				if got := nilImage.Workdir("/tmp"); got != nil {
					t.Fatalf("Workdir() = %+v, want nil", got)
				}

				image := BaseImage("alpine").RunCommands(123)
				if err := image.Err(); err == nil || !strings.Contains(err.Error(), "RunCommands accepts string or []string") {
					t.Fatalf("Err() = %v, want RunCommands type error", err)
				}
				before := image.Dockerfile()
				image.RunCommands("echo after-error").Env(map[string]string{"A": "b"}).Entrypoint("sh").Cmd("echo").User("root").Expose(80)
				if got := image.Dockerfile(); got != before {
					t.Fatalf("Dockerfile mutated after error: %q != %q", got, before)
				}
			},
		},
		{
			name: "docker_quote_and_optional_skips",
			run: func(t *testing.T) {
				image := BaseImage("alpine").
					RunCommands("", []string{"echo hi", "", "echo bye"}).
					Env(map[string]string{"PLAIN": "alpha-1", "QUOTED": `needs "quotes"`}).
					Entrypoint().
					Cmd().
					Expose(443)
				if err := image.Err(); err != nil {
					t.Fatalf("Err() = %v", err)
				}
				got := image.Dockerfile()
				if !strings.Contains(got, "RUN echo hi && echo bye\n") {
					t.Fatalf("Dockerfile() missing joined RUN: %q", got)
				}
				if !strings.Contains(got, `PLAIN=alpha-1`) || !strings.Contains(got, `QUOTED="needs \"quotes\""`) {
					t.Fatalf("Dockerfile() missing expected ENV quoting: %q", got)
				}
				if !strings.Contains(got, "ENTRYPOINT null\n") || !strings.Contains(got, "CMD null\n") {
					t.Fatalf("Dockerfile() missing empty JSON directives: %q", got)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
