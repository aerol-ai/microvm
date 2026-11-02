package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/gvisorpids"
)

// snapshotHelperPrefix names the short-lived container CreateSnapshot commits
// the final image from. It never starts and never collides with a sandbox ID.
const snapshotHelperPrefix = "snapcommit-"

// snapshotHelperMaxAge is how long the orphan sweep leaves a snapshot helper
// alone. The helper lives only for one commit of a container that never ran,
// which takes seconds; this just has to outlast the slowest.
const snapshotHelperMaxAge = 10 * time.Minute

// snapshotInternalEnvKeys are the variables the driver itself puts in a
// sandbox container's env. A snapshot keeps none of their values, even when
// its base image (an older snapshot) still holds one: the toolbox token and
// the ready-socket nonce are this sandbox's credentials, and the rest describe
// this sandbox only. Every create sets them again.
var snapshotInternalEnvKeys = map[string]bool{
	"SB_TOOLBOX_TOKEN": true,
	"SB_TOOLBOX_PORT":  true,
	"SB_SANDBOX_ID":    true,
	poolParkedEnv:      true,
	readySocketEnv:     true,
	readyNonceEnv:      true,
	gvisorpids.EnvVar:  true,
}

// CreateSnapshot commits a sandbox container into the image imageRef.
//
// A plain Docker commit copies the container's whole env into the image, and
// that env holds the sandbox's toolbox token and every variable its create
// passed (API keys included), which AerolVM otherwise keeps sealed. The image
// is distributed (snapshot push), so it must carry neither:
//
//  1. The commit gets an explicit config: the container's own, with every
//     variable the create added cleared (snapshotEnv). Docker cannot drop a
//     key in a commit (it merges the container's env back for any key the
//     config omits), so cleared keys stay with an empty value.
//  2. The graphdriver image store also writes the container's original config,
//     env included, into the image's container_config, whatever the commit's
//     config says. So that commit stays an untagged intermediate, and the
//     tagged image is committed from a helper container created from it,
//     whose own config is already clean. The pushed config is the tagged
//     image's only.
//
// The intermediate is deleted where Docker allows it (the containerd image
// store). The graphdriver store keeps it as the tagged image's parent, local
// to this node, and removes it when the snapshot image is deleted.
func (c *Client) CreateSnapshot(ctx context.Context, containerRef, imageRef string) (string, error) {
	repo, tag, err := splitSnapshotImageRef(imageRef)
	if err != nil {
		return "", err
	}
	containerRef = strings.TrimSpace(containerRef)

	source, err := c.inspectSnapshotSource(ctx, containerRef)
	if err != nil {
		return "", err
	}
	baseEnv, err := c.snapshotBaseEnv(ctx, source.image)
	if err != nil {
		return "", err
	}
	config, err := source.configWithEnv(snapshotEnv(source.env, baseEnv))
	if err != nil {
		return "", err
	}

	query := url.Values{}
	query.Set("container", containerRef)
	intermediate, err := c.commit(ctx, query, config)
	if err != nil {
		return "", fmt.Errorf("commit snapshot: %w", err)
	}
	return c.recommitSnapshot(ctx, intermediate, repo, tag)
}

// recommitSnapshot commits the tagged snapshot image from a helper container
// made from the intermediate commit, so the tagged image's recorded container
// config is the helper's clean one rather than the sandbox's. The helper and,
// where Docker allows, the intermediate are removed on every path; the
// cleanups use a context the caller's cancellation cannot cut short.
func (c *Client) recommitSnapshot(ctx context.Context, intermediate, repo, tag string) (string, error) {
	cleanupCtx := context.WithoutCancel(ctx)
	defer c.dropSnapshotIntermediate(cleanupCtx, intermediate)

	name, err := snapshotHelperName()
	if err != nil {
		return "", err
	}
	helper := map[string]any{
		"Image": intermediate,
		// Never started; no network so nothing is allocated for it.
		"HostConfig": map[string]any{"NetworkMode": "none"},
	}
	if err := c.doJSON(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, helper, nil, nil); err != nil {
		return "", fmt.Errorf("commit snapshot: create helper: %w", err)
	}
	defer func() {
		if err := c.removeContainer(cleanupCtx, name, true); err != nil {
			c.warn("snapshot helper container not removed; the orphan sweep reclaims it once it is stale",
				"container", name, "error", err)
		}
	}()

	query := url.Values{}
	query.Set("container", name)
	query.Set("repo", repo)
	if tag != "" {
		query.Set("tag", tag)
	}
	// The helper never ran, so there is nothing to pause.
	query.Set("pause", "false")
	id, err := c.commit(ctx, query, nil)
	if err != nil {
		return "", fmt.Errorf("commit snapshot: %w", err)
	}
	return id, nil
}

// dropSnapshotIntermediate deletes the untagged intermediate commit. Docker
// refuses (409) while the graphdriver store keeps it as the snapshot image's
// parent; that is expected and leaves it to go with the snapshot image.
func (c *Client) dropSnapshotIntermediate(ctx context.Context, intermediate string) {
	if err := c.RemoveImage(ctx, intermediate); err != nil {
		c.warn("snapshot intermediate image not removed", "image", intermediate, "error", err)
	}
}

func (c *Client) commit(ctx context.Context, query url.Values, config map[string]json.RawMessage) (string, error) {
	var body any
	if config != nil {
		body = config
	}
	var response struct {
		ID string `json:"Id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/commit", query, body, nil, &response); err != nil {
		return "", err
	}
	id := strings.TrimSpace(response.ID)
	if id == "" {
		return "", errors.New("docker returned no image id")
	}
	return id, nil
}

func (c *Client) warn(msg string, args ...any) {
	if c != nil && c.logger != nil {
		c.logger.Warn(msg, args...)
	}
}

// snapshotSource is the part of a container inspect a snapshot commit needs.
// config is kept as raw JSON so every field Docker reports goes back into the
// commit unchanged; only Env is rewritten.
type snapshotSource struct {
	image  string
	config map[string]json.RawMessage
	env    []string
}

func (c *Client) inspectSnapshotSource(ctx context.Context, containerRef string) (snapshotSource, error) {
	var inspect struct {
		Image  string          `json:"Image"`
		Config json.RawMessage `json:"Config"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(containerRef)+"/json", nil, nil, nil, &inspect); err != nil {
		return snapshotSource{}, fmt.Errorf("commit snapshot: inspect container: %w", err)
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(inspect.Config, &config); err != nil || config == nil {
		return snapshotSource{}, fmt.Errorf("commit snapshot: container %s reports no config", containerRef)
	}
	var env []string
	if raw, ok := config["Env"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &env); err != nil {
			return snapshotSource{}, fmt.Errorf("commit snapshot: container env: %w", err)
		}
	}
	image := strings.TrimSpace(inspect.Image)
	if image == "" {
		return snapshotSource{}, fmt.Errorf("commit snapshot: container %s reports no image", containerRef)
	}
	return snapshotSource{image: image, config: config, env: env}, nil
}

// snapshotBaseEnv reads the env of the image the container was created from,
// by ID, so a tag moved since then does not change the answer. Without it the
// commit cannot tell the image's own variables from the ones the create
// added, so a failure fails the snapshot rather than guessing.
func (c *Client) snapshotBaseEnv(ctx context.Context, imageID string) ([]string, error) {
	var inspect struct {
		Config struct {
			Env []string `json:"Env"`
		} `json:"Config"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/images/"+url.PathEscape(imageID)+"/json", nil, nil, nil, &inspect); err != nil {
		return nil, fmt.Errorf("commit snapshot: inspect base image: %w", err)
	}
	return inspect.Config.Env, nil
}

func (s snapshotSource) configWithEnv(env []string) (map[string]json.RawMessage, error) {
	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	config := make(map[string]json.RawMessage, len(s.config))
	for key, value := range s.config {
		config[key] = value
	}
	config["Env"] = encoded
	return config, nil
}

// snapshotEnv is the env a snapshot image keeps, given the container's env
// and the env of the image it was created from. Docker's container env is the
// create's variables plus the image's for keys the create did not set, so:
//
//   - a key the image has with the same value is the image's own (PATH, LANG):
//     it is kept as is;
//   - a key the image has with another value was overridden by the create: it
//     goes back to the image's value;
//   - a key the image lacks was added by the create (user env, driver
//     variables): it is cleared.
//
// The driver's own keys (snapshotInternalEnvKeys) are cleared whatever the
// image holds. The order of the container's env is kept.
func snapshotEnv(containerEnv, baseEnv []string) []string {
	base := make(map[string]string, len(baseEnv))
	for _, kv := range baseEnv {
		key, value, _ := strings.Cut(kv, "=")
		if _, seen := base[key]; !seen {
			base[key] = value
		}
	}
	out := make([]string, 0, len(containerEnv))
	seen := make(map[string]bool, len(containerEnv))
	for _, kv := range containerEnv {
		key, value, _ := strings.Cut(kv, "=")
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		baseValue, inBase := base[key]
		switch {
		case snapshotInternalEnvKeys[key]:
			out = append(out, key+"=")
		case inBase && baseValue == value:
			out = append(out, kv)
		case inBase:
			out = append(out, key+"="+baseValue)
		default:
			out = append(out, key+"=")
		}
	}
	return out
}

// isLiveSnapshotHelper reports whether a container is a snapshot helper
// young enough that its snapshot may still be running. The helper is made
// from the sandbox's own committed image, so it carries the sandbox's managed
// label, and the orphan sweep would otherwise see a container with no row and
// remove it between the helper's create and its commit. A helper older than
// snapshotHelperMaxAge was left by a crash, and the sweep may reap it.
func isLiveSnapshotHelper(summary containerSummary, now time.Time) bool {
	for _, name := range summary.Names {
		if strings.HasPrefix(strings.TrimPrefix(name, "/"), snapshotHelperPrefix) {
			return now.Sub(time.Unix(summary.Created, 0)) < snapshotHelperMaxAge
		}
	}
	return false
}

func snapshotHelperName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("commit snapshot: helper name: %w", err)
	}
	return snapshotHelperPrefix + hex.EncodeToString(b), nil
}
