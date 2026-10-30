package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// `sandboxd key rotate` (plans/customer-key-custody.md §13, eng D26): each
// step only edits this node's server-key file; the operator copies it to
// every node, and each daemon takes the step at its next re-read (about
// SB_SECRET_PROVIDER_RECHECK_INTERVAL) with no restart.

// keyRing is the ring being edited, with how to save it for the custody in
// use.
type keyRing struct {
	path     string
	entries  []secrets.RingEntry
	newEntry func(ctx context.Context, id uint32) (secrets.RingEntry, error)
	save     func(ctx context.Context, entries []secrets.RingEntry) error
}

// ringGateTimeout bounds the call to the local daemon's members API.
const ringGateTimeout = 10 * time.Second

// fetchRingGate asks the local daemon whether every live member runs a
// build that reads a ring (cluster.ServerKeyRingAllowed); tests replace it.
// lagging names the live members on an older build.
var fetchRingGate = func(ctx context.Context, cfg config.Config) (ready, known bool, lagging []string, err error) {
	host := cfg.APIHost
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(ctx, ringGateTimeout)
	defer cancel()
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.APIPort)) + "/v1/cluster/members"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.PATToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, false, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, false, nil, fmt.Errorf("%s: %s %s", url, resp.Status, strings.TrimSpace(string(body)))
	}
	var body struct {
		Members []cluster.Member `json:"members"`
		Ready   *bool            `json:"server_key_ring_ready"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return false, false, nil, fmt.Errorf("%s: %w", url, err)
	}
	for _, m := range body.Members {
		if m.Alive && m.FSMOpsVersion < cluster.ServerKeyRingFSMOpsVersion {
			lagging = append(lagging, fmt.Sprintf("%s (fv %d)", m.NodeID, m.FSMOpsVersion))
		}
	}
	if body.Ready == nil {
		return false, false, lagging, nil
	}
	return *body.Ready, true, lagging, nil
}

// checkRingGate refuses a stage until every live member reads a ring: an
// older build refuses to boot from the ring file and cannot open blobs that
// name their key.
func checkRingGate(ctx context.Context, cfg config.Config) error {
	if !cfg.EnableCluster {
		return nil
	}
	ready, known, lagging, err := fetchRingGate(ctx, cfg)
	switch {
	case err != nil:
		return fmt.Errorf("refusing to stage: cannot ask the local sandboxd whether every member reads a server-key ring (run this on a node whose sandboxd is up): %w", err)
	case !known:
		return errors.New("refusing to stage: the running sandboxd predates server-key rotation; upgrade every node first")
	case len(lagging) > 0:
		return fmt.Errorf("refusing to stage: these members run a build that cannot read a server-key ring; upgrade them first: %s", strings.Join(lagging, ", "))
	case !ready:
		return errors.New("refusing to stage: this node has not rejoined its cluster yet, so it cannot tell whether every member is upgraded; retry in a minute")
	}
	return nil
}

// openKeyRing reads the ring of the custody in use and runs fn with it.
func openKeyRing(ctx context.Context, cfg config.Config, fn func(context.Context, *keyRing) error) error {
	if cfg.CredentialKeyCustody == secrets.CustodyWrapped {
		path := cfg.CredentialKeyWrappedPath
		f, err := secrets.ReadWrappedKeyFile(path)
		if err != nil {
			return err
		}
		return withKeyStore(ctx, cfg, func(ctx context.Context, w secrets.DataKeyWrapper) error {
			// Never edit a ring this node cannot open.
			if _, err := secrets.UnwrapRing(ctx, w, f, nil); err != nil {
				return err
			}
			return fn(ctx, &keyRing{
				path:    path,
				entries: f.Entries(),
				newEntry: func(ctx context.Context, id uint32) (secrets.RingEntry, error) {
					return secrets.NewRingEntry(ctx, id, w)
				},
				save: func(ctx context.Context, entries []secrets.RingEntry) error {
					nf := f
					if err := nf.SetEntries(entries); err != nil {
						return err
					}
					if e := entryByID(entries, 0); e.State == secrets.RingStateRetired {
						// The plaintext-era key is gone: old copies of it
						// open nothing current (eng D24).
						nf.MigratedFromPlaintext = false
					}
					// The running daemon's rewrap sweep may have edited the
					// file since it was read; never undo that.
					if err := secrets.ReplaceWrappedKeyFile(path, f, nf); err != nil {
						return err
					}
					back, err := secrets.ReadWrappedKeyFile(path)
					if err != nil {
						return err
					}
					if _, err := secrets.UnwrapRing(ctx, w, back, nil); err != nil {
						return fmt.Errorf("verify %s: %w", path, err)
					}
					return nil
				},
			})
		})
	}
	path := cfg.KeyRingPath()
	var entries []secrets.RingEntry
	if fileExists(path) {
		f, err := secrets.ReadKeyRingFile(path)
		if err != nil {
			return err
		}
		entries = f.Ring
	} else {
		key, ok, err := secrets.LoadPlaintextKey(cfg.CredentialEncryptionKey, cfg.CredentialEncryptionKeyPath)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no server key to rotate (SB_CREDENTIAL_ENCRYPTION_KEY, %s or %s)", cfg.CredentialEncryptionKeyPath, path)
		}
		entries = []secrets.RingEntry{secrets.LegacyRingEntry(key)}
	}
	ctx, cancel := context.WithTimeout(ctx, keyCallTimeout)
	defer cancel()
	return fn(ctx, &keyRing{
		path:    path,
		entries: entries,
		newEntry: func(ctx context.Context, id uint32) (secrets.RingEntry, error) {
			return secrets.NewRingEntry(ctx, id, nil)
		},
		save: func(_ context.Context, entries []secrets.RingEntry) error {
			if err := secrets.WriteKeyRingFile(path, secrets.KeyRingFile{Ring: entries}); err != nil {
				return err
			}
			_, err := secrets.ReadKeyRingFile(path)
			return err
		},
	})
}

func entryByID(entries []secrets.RingEntry, id uint32) secrets.RingEntry {
	for _, e := range entries {
		if e.ID == id {
			return e
		}
	}
	return secrets.RingEntry{}
}

// keyRotate runs one rotation step: "stage", "promote" or "retire" (with
// retireID).
func keyRotate(ctx context.Context, cfg config.Config, step string, retireID uint32, out io.Writer) error {
	if step == "stage" {
		if err := checkRingGate(ctx, cfg); err != nil {
			return err
		}
	}
	return openKeyRing(ctx, cfg, func(ctx context.Context, r *keyRing) error {
		switch step {
		case "stage":
			e, err := r.newEntry(ctx, secrets.NextRingID(r.entries))
			if err != nil {
				return err
			}
			next, err := secrets.StageRingKey(r.entries, e)
			if err != nil {
				return err
			}
			if err := r.save(ctx, next); err != nil {
				return err
			}
			fmt.Fprintf(out, `staged: key %d (decrypt only) in %s
next:
  1. copy %s to every node%s
  2. wait until aerolvm_server_key_ring{key="%d",key2="decrypt"} shows on every member (within SB_SECRET_PROVIDER_RECHECK_INTERVAL)
  3. sandboxd key rotate --promote, and copy the file again
`, e.ID, r.path, r.path, plaintextNote(cfg), e.ID)
		case "promote":
			next, from, to, err := secrets.PromoteRingKey(r.entries)
			if err != nil {
				return err
			}
			if err := r.save(ctx, next); err != nil {
				return err
			}
			fmt.Fprintf(out, `promoted: key %d is current, key %d is decrypt only, in %s
next:
  1. copy %s to every node%s; each node seals new data with key %d after its next re-read and reseals its rows
  2. wait until aerolvm_server_key_rows{key="%d"} is 0 and aerolvm_server_key_ring{key="%d",key2="current"} shows on every member
  3. sandboxd key rotate --retire %d, and copy the file again
`, to, from, r.path, r.path, plaintextNote(cfg), to, from, to, from)
		case "retire":
			next, err := secrets.RetireRingKey(r.entries, retireID)
			if err != nil {
				return err
			}
			if err := r.save(ctx, next); err != nil {
				return err
			}
			fmt.Fprintf(out, "retired: key %d is gone from %s\nnext: copy %s to every node%s\n", retireID, r.path, r.path, plaintextNote(cfg))
			if retireID == 0 && cfg.CredentialKeyCustody != secrets.CustodyWrapped {
				fmt.Fprintf(out, "then remove the retired key itself: SB_CREDENTIAL_ENCRYPTION_KEY from the env files and the key file %s, on every node\n", cfg.CredentialEncryptionKeyPath)
			}
		default:
			return fmt.Errorf("unknown rotation step %q", step)
		}
		return nil
	})
}

// plaintextNote also reminds that a node joining later needs the file: the
// cred bundle from cluster-init holds the key as it was then.
func plaintextNote(cfg config.Config) string {
	join := ", and into the cred bundle future joiners use"
	if cfg.CredentialKeyCustody == secrets.CustodyWrapped {
		return " (it is ciphertext)" + join
	}
	return " (it holds the keys in plaintext: copy it like the key file, over a secure channel, mode 0600)" + join
}

// ringLines describes a ring for `sandboxd key status`.
func ringLines(entries []secrets.RingEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf("%d=%s", e.ID, e.State))
	}
	return strings.Join(parts, " ")
}
