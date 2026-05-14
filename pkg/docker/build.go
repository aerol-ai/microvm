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

	"golang.org/x/sync/singleflight"

	"github.com/aerol-ai/microvm/pkg/models"
)

// buildGroup deduplicates concurrent BuildImage calls that share a tag.
// Two requests landing simultaneously for the same content-addressed tag
// would otherwise both upload the tar context and ask the daemon to build —
// Docker's layer cache makes the second build fast, but the tar upload and
// daemon-side serialization still costs work. With singleflight, the second
// (and Nth) caller waits for the first build's result and returns the same
// error/success. The key is the tag because that's content-addressed: the
// same tag means the same dockerfile bytes (see BuildTagFor).
var buildGroup singleflight.Group

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
	_, err, _ := buildGroup.Do(tag, func() (any, error) {
		return nil, c.buildImageLocked(ctx, tag, req)
	})
	return err
}

func (c *Client) buildImageLocked(ctx context.Context, tag string, req BuildImageRequest) error {
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

// PushImageRequest is the input to (*Client).PushImage. SourceTag is the
// local image (typically an aerolvm-build/<sha>:latest tag returned by
// BuildImage). DestRef is the fully-qualified destination, e.g.
// "ghcr.io/my-org/my-image:v1.2.3"; if no ":tag" is present, "latest" is
// used. Auth is request-scoped credentials — they are sent to the daemon
// as a one-shot X-Registry-Auth header and never persisted.
type PushImageRequest struct {
	SourceTag string
	DestRef   string
	Auth      models.RegistryAuth
	OnLog     func(line string)
}

// PushImage tags SourceTag as DestRef and pushes the result to the
// destination registry. Returns the canonical "repo:tag" that was pushed.
//
// Credentials are passed through per-call via X-Registry-Auth; nothing is
// written to the daemon's auth config and nothing is logged. The local
// SourceTag is preserved after a successful push so a follow-up sandbox
// create still hits the local fast path.
func (c *Client) PushImage(ctx context.Context, req PushImageRequest) (string, error) {
	src := strings.TrimSpace(req.SourceTag)
	dest := strings.TrimSpace(req.DestRef)
	if src == "" {
		return "", errors.New("push image: source tag is required")
	}
	if dest == "" {
		return "", errors.New("push image: dest ref is required")
	}
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return "", errors.New("push image: auth username and password are required")
	}
	repo, tag := splitDestRef(dest)
	if repo == "" {
		return "", fmt.Errorf("push image: dest ref %q is missing a repository", dest)
	}
	if err := c.tagImage(ctx, src, repo, tag); err != nil {
		return "", err
	}

	encoded, err := json.Marshal(map[string]string{
		"username":      req.Auth.Username,
		"password":      req.Auth.Password,
		"serveraddress": req.Auth.Server,
	})
	if err != nil {
		return "", fmt.Errorf("marshal push registry auth: %w", err)
	}
	authHeader := base64.StdEncoding.EncodeToString(encoded)

	query := url.Values{}
	query.Set("tag", tag)
	target := "http://docker/images/" + url.PathEscape(repo) + "/push?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return "", fmt.Errorf("push image: %w", err)
	}
	request.Header.Set("X-Registry-Auth", authHeader)

	response, err := c.streamClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("push image: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 {
		data, _ := io.ReadAll(response.Body)
		return "", fmt.Errorf("docker API POST /images/%s/push failed with status %d: %s",
			repo, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := decodePushStream(response.Body, req.OnLog); err != nil {
		return "", err
	}
	return repo + ":" + tag, nil
}

// splitDestRef splits "host[:port]/repo:tag" into (repo, tag). Tag defaults
// to "latest" when missing. The colon search is anchored after the last
// slash so a registry "host:port" prefix isn't mistaken for the tag.
func splitDestRef(ref string) (repo, tag string) {
	slash := strings.LastIndex(ref, "/")
	tail := ref
	prefix := ""
	if slash >= 0 {
		prefix = ref[:slash+1]
		tail = ref[slash+1:]
	}
	if colon := strings.LastIndex(tail, ":"); colon >= 0 {
		return prefix + tail[:colon], tail[colon+1:]
	}
	return ref, "latest"
}

func (c *Client) tagImage(ctx context.Context, sourceRef, repo, tag string) error {
	query := url.Values{}
	query.Set("repo", repo)
	query.Set("tag", tag)
	if err := c.doJSON(ctx, http.MethodPost,
		"/images/"+url.PathEscape(sourceRef)+"/tag", query, nil, nil, nil); err != nil {
		return fmt.Errorf("tag image %s as %s:%s: %w", sourceRef, repo, tag, err)
	}
	return nil
}

func decodePushStream(body io.Reader, onLog func(line string)) error {
	decoder := json.NewDecoder(body)
	for {
		var msg struct {
			Status      string `json:"status"`
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := decoder.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("decode push stream: %w", err)
		}
		if msg.ErrorDetail.Message != "" {
			return fmt.Errorf("push image: %s", msg.ErrorDetail.Message)
		}
		if msg.Error != "" {
			return fmt.Errorf("push image: %s", msg.Error)
		}
		if onLog != nil && msg.Status != "" {
			onLog(msg.Status)
		}
	}
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

// BuiltImage is the slice of Docker's image-list payload that the built-image
// janitor needs: one of the locally-built image's RepoTags (always in the
// BuiltImageNamespace) plus when the daemon reported it was created. Multiple
// RepoTags per image are possible if the same content was tagged twice; we
// surface each tag as its own BuiltImage so the GC decision is per-tag.
type BuiltImage struct {
	// Tag is one of the image's RepoTags, qualified (e.g.
	// "aerolvm-build/abc123:latest").
	Tag string
	// CreatedAt is the daemon-reported creation time, UTC.
	CreatedAt time.Time
}

// ListBuiltImages returns every locally-built image (tags in
// BuiltImageNamespace) the daemon currently holds. The janitor uses this
// to find candidates for unreferenced-and-old removal.
//
// We filter server-side by reference so the API call only returns matching
// images — much cheaper than pulling the whole image list and filtering
// client-side on a daemon that may hold hundreds of base images.
func (c *Client) ListBuiltImages(ctx context.Context) ([]BuiltImage, error) {
	filters, err := json.Marshal(map[string][]string{
		"reference": {BuiltImageNamespace + "/*"},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal filters: %w", err)
	}
	query := url.Values{}
	query.Set("filters", string(filters))

	var payload []struct {
		RepoTags []string `json:"RepoTags"`
		Created  int64    `json:"Created"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/images/json", query, nil, nil, &payload); err != nil {
		return nil, fmt.Errorf("list built images: %w", err)
	}

	out := make([]BuiltImage, 0, len(payload))
	for _, entry := range payload {
		created := time.Unix(entry.Created, 0).UTC()
		for _, tag := range entry.RepoTags {
			if !strings.HasPrefix(tag, BuiltImageNamespace+"/") {
				// Docker's reference filter is glob-y; defensively skip anything
				// outside our namespace so an aliased tag can't get GC'd.
				continue
			}
			out = append(out, BuiltImage{Tag: tag, CreatedAt: created})
		}
	}
	return out, nil
}
