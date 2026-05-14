package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// BuiltImageNamespace is the local image-name prefix every Daytona-facade
// build is tagged with. Keeping every built image under a single namespace
// makes them trivially identifiable by image GC (pkg/docker/image_gc.go) and
// keeps them out of the way of pulled images.
const BuiltImageNamespace = "aerolvm-build"

// BuildImageRequest is the input to (*Client).BuildImage.
//
// DockerfileContent is mandatory. ContextTar is optional — when nil, the
// build context contains just the Dockerfile. Tag is the image name to tag
// the result with; it should already be qualified (e.g. registry/name:tag)
// if the caller intends to push it.
type BuildImageRequest struct {
	Tag               string
	DockerfileContent string
	ContextTar        []byte
	Registry          *models.RegistryAuth
	OnLog             func(line string)
}

// BuildImage drives `POST /build` against the local Docker daemon and tags
// the resulting image with req.Tag. Streams build progress as NDJSON; if
// req.OnLog is set, each `stream` chunk is forwarded line-by-line.
//
// Idempotent: tagging the same Dockerfile content+context twice with the
// same tag is a no-op for the daemon — it returns the cached image hash.
func (c *Client) BuildImage(ctx context.Context, req BuildImageRequest) error {
	tag := strings.TrimSpace(req.Tag)
	if tag == "" {
		return errors.New("build image: tag is required")
	}
	dockerfile := strings.TrimRight(req.DockerfileContent, "\n") + "\n"
	if strings.TrimSpace(dockerfile) == "" {
		return errors.New("build image: dockerfile content is required")
	}

	contextTar, err := assembleBuildContext(dockerfile, req.ContextTar)
	if err != nil {
		return err
	}

	headers := map[string]string{
		"Content-Type": "application/x-tar",
	}
	if req.Registry != nil && req.Registry.Username != "" {
		// Docker's /build endpoint accepts X-Registry-Config (a JSON map of
		// server→auth) for pulls of FROM bases that need authentication.
		auth := map[string]map[string]string{
			req.Registry.Server: {
				"username":      req.Registry.Username,
				"password":      req.Registry.Password,
				"serveraddress": req.Registry.Server,
			},
		}
		encoded, marshalErr := json.Marshal(auth)
		if marshalErr != nil {
			return fmt.Errorf("marshal build registry auth: %w", marshalErr)
		}
		headers["X-Registry-Config"] = base64.URLEncoding.EncodeToString(encoded)
	}

	query := url.Values{}
	query.Set("t", tag)
	query.Set("dockerfile", "Dockerfile")
	query.Set("rm", "true")
	query.Set("forcerm", "true")

	target := "http://docker/build?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(contextTar))
	if err != nil {
		return fmt.Errorf("build image: %w", err)
	}
	for k, v := range headers {
		request.Header.Set(k, v)
	}

	// Use streamClient (no timeout) — builds can take minutes. We surface
	// a real deadline through ctx instead.
	response, err := c.streamClient.Do(request)
	if err != nil {
		return fmt.Errorf("build image: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		data, _ := io.ReadAll(response.Body)
		return fmt.Errorf("docker API POST /build failed with status %d: %s",
			response.StatusCode, strings.TrimSpace(string(data)))
	}

	return decodeBuildStream(response.Body, req.OnLog)
}

// assembleBuildContext returns a tar containing the Dockerfile at the
// archive root. If extra is non-nil, its entries are concatenated after the
// Dockerfile — entries with the same name (in particular "Dockerfile") win
// from the extra tar to allow callers to ship their own.
//
// We don't try to merge or deduplicate beyond writing both streams: Docker's
// build tar reader uses the last-write-wins semantics for duplicate entries,
// which matches what we want.
func assembleBuildContext(dockerfile string, extra []byte) ([]byte, error) {
	if len(extra) > 0 {
		// When the caller supplied their own context, we trust it to include
		// a Dockerfile (the build query string is hardcoded to dockerfile=
		// "Dockerfile" — if it's missing, docker errors immediately with a
		// clear "Cannot locate specified Dockerfile" message).
		return extra, nil
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte(dockerfile)
	header := &tar.Header{
		Name:    "Dockerfile",
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: time.Unix(0, 0),
	}
	if err := tw.WriteHeader(header); err != nil {
		return nil, fmt.Errorf("write Dockerfile header: %w", err)
	}
	if _, err := tw.Write(body); err != nil {
		return nil, fmt.Errorf("write Dockerfile body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close build tar: %w", err)
	}
	return buf.Bytes(), nil
}

// decodeBuildStream consumes Docker's NDJSON build progress stream. Each
// entry is one of {stream, error, errorDetail, aux}. We forward `stream`
// lines to onLog (split at newlines, trimmed of trailing whitespace) and
// promote any `error` / `errorDetail.message` to a returned error.
func decodeBuildStream(body io.Reader, onLog func(line string)) error {
	decoder := json.NewDecoder(body)
	for {
		var msg struct {
			Stream      string `json:"stream"`
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode build stream: %w", err)
		}
		if msg.ErrorDetail.Message != "" {
			return fmt.Errorf("build image: %s", msg.ErrorDetail.Message)
		}
		if msg.Error != "" {
			return fmt.Errorf("build image: %s", msg.Error)
		}
		if onLog != nil && msg.Stream != "" {
			for _, line := range strings.Split(strings.TrimRight(msg.Stream, "\n"), "\n") {
				onLog(line)
			}
		}
	}
}

// BuildTagFor returns the deterministic local image tag for a given
// Dockerfile + optional context hash list. Same input → same tag → docker
// build is a no-op on the second call, which is what makes the createImage
// path idempotent under retries.
func BuildTagFor(dockerfile string, contextHashes []string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(dockerfile)))
	h.Write([]byte{0})
	for _, hash := range contextHashes {
		h.Write([]byte(strings.TrimSpace(hash)))
		h.Write([]byte{0})
	}
	digest := hex.EncodeToString(h.Sum(nil))[:16]
	return BuiltImageNamespace + "/" + digest + ":latest"
}

// ImageExists reports whether the named image already exists in the local
// daemon. Used by the daytona facade to short-circuit redundant builds.
func (c *Client) ImageExists(ctx context.Context, imageRef string) (bool, error) {
	_, err := c.inspectImage(ctx, imageRef)
	if err == nil {
		return true, nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "no such image") ||
		strings.Contains(err.Error(), "404") {
		return false, nil
	}
	return false, err
}
