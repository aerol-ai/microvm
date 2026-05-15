package microvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Image is a fluent Dockerfile builder for the Go SDK. Build it locally, then
// pass it to Client.BuildImage or Client.CreateWithImage.
type Image struct {
	dockerfile string
	err        error
}

// BaseImage starts a Dockerfile with FROM <image>.
func BaseImage(image string) *Image {
	trimmed := strings.TrimSpace(image)
	if trimmed == "" {
		return &Image{err: errors.New("BaseImage requires a non-empty image string")}
	}
	return &Image{dockerfile: fmt.Sprintf("FROM %s\n", trimmed)}
}

// FromDockerfile wraps an existing Dockerfile string and normalizes the final
// trailing newline so builds stay content-stable across callers.
func FromDockerfile(dockerfile string) *Image {
	if strings.TrimSpace(dockerfile) == "" {
		return &Image{err: errors.New("FromDockerfile requires a non-empty Dockerfile string")}
	}
	if !strings.HasSuffix(dockerfile, "\n") {
		dockerfile += "\n"
	}
	return &Image{dockerfile: dockerfile}
}

func (i *Image) Dockerfile() string {
	if i == nil {
		return ""
	}
	return i.dockerfile
}

func (i *Image) Err() error {
	if i == nil {
		return errors.New("image is nil")
	}
	return i.err
}

// RunCommands appends one RUN per string argument. A []string argument is
// joined with && so the commands share one layer.
func (i *Image) RunCommands(commands ...any) *Image {
	if i == nil || i.err != nil {
		return i
	}
	for _, entry := range commands {
		switch value := entry.(type) {
		case string:
			cmd := strings.TrimSpace(value)
			if cmd != "" {
				i.dockerfile += fmt.Sprintf("RUN %s\n", cmd)
			}
		case []string:
			parts := make([]string, 0, len(value))
			for _, item := range value {
				trimmed := strings.TrimSpace(item)
				if trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
			if len(parts) > 0 {
				i.dockerfile += fmt.Sprintf("RUN %s\n", strings.Join(parts, " && "))
			}
		default:
			i.err = fmt.Errorf("RunCommands accepts string or []string, got %T", entry)
			return i
		}
	}
	return i
}

// Env appends one ENV line containing all provided key/value pairs.
func (i *Image) Env(envVars map[string]string) *Image {
	if i == nil || i.err != nil || len(envVars) == 0 {
		return i
	}
	keys := make([]string, 0, len(envVars))
	for key := range envVars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, dockerQuote(envVars[key])))
	}
	i.dockerfile += fmt.Sprintf("ENV %s\n", strings.Join(parts, " "))
	return i
}

func (i *Image) Workdir(dirPath string) *Image {
	if i == nil || i.err != nil {
		return i
	}
	if strings.TrimSpace(dirPath) == "" {
		i.err = errors.New("Image.Workdir requires a non-empty path")
		return i
	}
	i.dockerfile += fmt.Sprintf("WORKDIR %s\n", dirPath)
	return i
}

func (i *Image) Entrypoint(commands ...string) *Image {
	if i == nil || i.err != nil {
		return i
	}
	encoded, err := json.Marshal(commands)
	if err != nil {
		i.err = fmt.Errorf("encode entrypoint: %w", err)
		return i
	}
	i.dockerfile += fmt.Sprintf("ENTRYPOINT %s\n", encoded)
	return i
}

func (i *Image) Cmd(commands ...string) *Image {
	if i == nil || i.err != nil {
		return i
	}
	encoded, err := json.Marshal(commands)
	if err != nil {
		i.err = fmt.Errorf("encode cmd: %w", err)
		return i
	}
	i.dockerfile += fmt.Sprintf("CMD %s\n", encoded)
	return i
}

func (i *Image) User(username string) *Image {
	if i == nil || i.err != nil {
		return i
	}
	if strings.TrimSpace(username) == "" {
		i.err = errors.New("Image.User requires a non-empty username")
		return i
	}
	i.dockerfile += fmt.Sprintf("USER %s\n", username)
	return i
}

func (i *Image) Expose(port int) *Image {
	if i == nil || i.err != nil {
		return i
	}
	if port < 1 || port > 65535 {
		i.err = fmt.Errorf("Image.Expose: port %d is out of range", port)
		return i
	}
	i.dockerfile += fmt.Sprintf("EXPOSE %d\n", port)
	return i
}

func dockerQuote(value string) string {
	if value == "" {
		return `""`
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !((r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '@')
	}) == -1 {
		return value
	}
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(value) + `"`
}
