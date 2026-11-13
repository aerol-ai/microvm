package nodejoin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/raftlogdir"
)

// AdoptOptions is `sandboxd adopt`.
type AdoptOptions struct {
	// CAKeyFile is a ca.key kept elsewhere (a backup); "" lets the server
	// use its CA store or fetch the key from another server.
	CAKeyFile string
}

// Adopter brings a cluster built with cluster-init.sh onto the join service
// (§4.4) from one of its servers.
type Adopter struct {
	Paths Paths
	Host  Host
	Printer
	LocalAPI string
}

// ErrNotAServer is adopt on a node that holds no Raft state.
var ErrNotAServer = errors.New("adopt runs on server nodes; workers and ingress nodes need nothing")

// Run asks this server to import the CA key (from the request, its CA
// store, or another server over mTLS) and to record every live member's
// current cert key as admitted, in one Raft op. Running it again changes
// nothing.
func (a *Adopter) Run(ctx context.Context, o AdoptOptions) (cluster.AdoptResponse, error) {
	if !a.Host.IsRoot() {
		return cluster.AdoptResponse{}, errors.New("run sandboxd adopt as root (sudo)")
	}
	env, err := loadNodeEnv(a.Paths)
	if err != nil {
		return cluster.AdoptResponse{}, err
	}
	if !env.clusterMode() {
		return cluster.AdoptResponse{}, errors.New("this node is not in a cluster (no SB_ENABLE_CLUSTER=true in cluster.env): start one with `sandboxd init`")
	}
	if role, err := joinRoleOf(env.get("SB_NODE_ROLE")); err != nil {
		return cluster.AdoptResponse{}, err
	} else if role != cluster.JoinRoleServer {
		return cluster.AdoptResponse{}, ErrNotAServer
	}
	var req cluster.AdoptRequest
	if o.CAKeyFile != "" {
		raw, err := os.ReadFile(o.CAKeyFile)
		if err != nil {
			return cluster.AdoptResponse{}, err
		}
		req.CAKey = string(raw)
	} else if raw, err := os.ReadFile(filepath.Join(env.caDir(a.Paths), "ca.key")); err == nil {
		// cluster-init.sh left ca.key on the seed; hand it over explicitly
		// so a CA store the daemon could not read still gets imported.
		req.CAKey = string(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	res, err := env.localAPI(a.LocalAPI).adopt(ctx, req)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && strings.Contains(ae.message, "no CA key here") {
			return res, fmt.Errorf("%w\nfix: run `sudo sandboxd adopt` on the seed (the server that ran cluster-init.sh) first, or pass --ca-key with a saved copy of its /etc/sandboxd/cluster-ca/ca.key", err)
		}
		return res, err
	}
	a.printf("cluster %s adopted on this server (CA key from %s, imported: %t)\n", res.ClusterID, res.CASource, res.CAImported)
	a.printf("admitted now: %s\n", listOrNone(res.Admitted))
	a.printf("admitted before: %s\n", listOrNone(res.Already))
	if len(res.Skipped) > 0 {
		ids := make([]string, 0, len(res.Skipped))
		for id := range res.Skipped {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			a.printf("skipped %s: %s\n", id, res.Skipped[id])
		}
		a.printf("note: a skipped node keeps working; run adopt again once it is reachable, or re-join it with a token\n")
	}
	a.printf("next: run `sudo sandboxd adopt` on every other server, then add nodes with `aerolvm join-command`\n")
	return res, nil
}

func listOrNone(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

// ResetOptions is `sandboxd reset`.
type ResetOptions struct {
	// Yes is the confirmation: reset deletes this node's cluster state.
	Yes bool
}

// Resetter takes this machine out of its cluster (kubeadm reset).
type Resetter struct {
	Paths Paths
	Host  Host
	Printer
	LocalAPI string
}

// ErrResetNeedsYes is a reset without --yes.
var ErrResetNeedsYes = errors.New("reset removes this node from its cluster and deletes its cluster state (cluster.env, certs, Raft data); run it again with --yes")

// Run asks the cluster to delete this node (when it can reach it), stops
// sandboxd and removes cluster.env, the drop-in, the certs and keys, the CA
// store and the Raft data. The database, the server key and sandboxd.env
// stay, so `systemctl start sandboxd` runs it as a single node again, and
// `sandboxd join` makes a new key for a fresh join. Safe to repeat.
func (r *Resetter) Run(ctx context.Context, o ResetOptions) error {
	if !o.Yes {
		return ErrResetNeedsYes
	}
	if !r.Host.IsRoot() {
		return errors.New("run sandboxd reset as root (sudo)")
	}
	env, err := loadNodeEnv(r.Paths)
	if err != nil {
		return err
	}
	nodeID := env.get("SB_NODE_ID")
	if env.clusterMode() && nodeID != "" {
		dctx, cancel := context.WithTimeout(ctx, time.Minute)
		res, err := env.localAPI(r.LocalAPI).deleteNode(dctx, nodeID)
		cancel()
		if err != nil {
			r.printf("warning: could not remove %s from the cluster (%v); from any machine, run: aerolvm delete node %s\n", nodeID, err, nodeID)
		} else {
			r.printf("removed %s from the cluster (denied: %t)\n", nodeID, res.Denied)
		}
	}
	if err := r.Host.StopSandboxd(ctx); err != nil {
		r.printf("warning: %v\n", err)
	}
	tlsDir, caDir, raftDir := env.tlsDir(r.Paths), env.caDir(r.Paths), env.raftDir(r.Paths)
	var removed []string
	for _, path := range []string{
		r.Paths.ClusterEnv, r.Paths.DropIn,
		filepath.Join(tlsDir, "ca.crt"), filepath.Join(tlsDir, "node.crt"), filepath.Join(tlsDir, "node.key"), filepath.Join(tlsDir, "node.csr"),
		filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"), filepath.Join(caDir, "ca.srl"),
	} {
		err := os.Remove(path)
		switch {
		case err == nil:
			removed = append(removed, path)
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	// A log SB_RAFT_WAL_DIR put on a disk of its own goes too, first: left
	// behind, the next start would find a log its Raft directory does not
	// name, and refuse it.
	walDir, err := raftlogdir.Recorded(raftDir)
	if err != nil {
		return err
	}
	if walDir != "" && dirHasEntries(walDir) {
		if err := removeTree(walDir); err != nil {
			return err
		}
		removed = append(removed, walDir)
	}
	if dirHasEntries(raftDir) {
		if err := removeTree(raftDir); err != nil {
			return err
		}
		removed = append(removed, raftDir)
	}
	if err := r.Host.DaemonReload(ctx); err != nil {
		r.printf("warning: %v\n", err)
	}
	if len(removed) == 0 {
		r.printf("nothing to reset: this machine holds no cluster state\n")
		return nil
	}
	r.printf("removed: %s\n", strings.Join(removed, ", "))
	r.printf("this machine is out of the cluster and sandboxd is stopped; join again with `sandboxd join`, or run it alone with `systemctl start sandboxd`\n")
	return nil
}

// removeTree deletes a Raft data directory, refusing a path too short to
// be one (a typo in SB_RAFT_DATA_DIR must not empty /var).
func removeTree(dir string) error {
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) || strings.Count(clean, string(filepath.Separator)) < 3 {
		return fmt.Errorf("refusing to delete %q: it does not look like a Raft data directory (set SB_RAFT_DATA_DIR, or delete it by hand)", dir)
	}
	return os.RemoveAll(clean)
}
