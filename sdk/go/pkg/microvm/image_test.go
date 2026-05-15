package microvm

import "testing"

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
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
