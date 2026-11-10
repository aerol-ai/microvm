package nodejoin

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// nodeEnv is what the node's env files say: sandboxd.env with cluster.env
// on top, the way systemd loads them.
type nodeEnv struct {
	base    map[string]string // sandboxd.env
	cluster map[string]string // cluster.env
	merged  map[string]string
}

func loadNodeEnv(p Paths) (nodeEnv, error) {
	base, err := readEnvFile(p.EnvFile)
	if err != nil {
		return nodeEnv{}, err
	}
	clusterEnv, err := readEnvFile(p.ClusterEnv)
	if err != nil {
		return nodeEnv{}, err
	}
	merged := maps.Clone(base)
	maps.Copy(merged, clusterEnv)
	return nodeEnv{base: base, cluster: clusterEnv, merged: merged}, nil
}

func (e nodeEnv) get(key string) string { return strings.TrimSpace(e.merged[key]) }

func (e nodeEnv) getOr(key, def string) string {
	if v := e.get(key); v != "" {
		return v
	}
	return def
}

// installed reports whether install.sh set this machine up.
func installed(p Paths) error {
	if _, err := os.Stat(p.EnvFile); err != nil {
		return fmt.Errorf("%s is missing: install AerolVM first (curl -fsSL %s | sudo bash), or run this through the installer", p.EnvFile, DefaultInstallerURL)
	}
	return nil
}

// clusterMode reports whether this node already runs in cluster mode.
func (e nodeEnv) clusterMode() bool {
	return strings.EqualFold(e.get("SB_ENABLE_CLUSTER"), "true")
}

func (e nodeEnv) apiPort() string { return e.getOr("SB_API_PORT", defaultAPIPort) }

// localAPI is this node's API on loopback.
func (e nodeEnv) localAPI(base string) *localAPI {
	if base == "" {
		base = "http://127.0.0.1:" + e.apiPort()
	}
	return &localAPI{base: base, pat: e.get("SB_PAT_TOKEN")}
}

// firecracker reports whether this node runs Firecracker VMs.
func (e nodeEnv) firecracker() bool {
	return strings.EqualFold(e.get("SB_ENABLE_FIRECRACKER"), "true")
}

// credentialKeyPath and wrappedKeyPath are where the server key lives,
// with the daemon's defaults.
func (e nodeEnv) credentialKeyPath() string {
	return e.getOr("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", "/var/lib/sandboxd/credential_encryption.key")
}

func (e nodeEnv) wrappedKeyPath() string {
	return e.getOr("SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH", "/var/lib/sandboxd/credential_encryption.key.wrapped")
}

// tlsDir and caDir honour a node that moved them.
func (e nodeEnv) tlsDir(p Paths) string { return e.getOr("SB_CLUSTER_TLS_DIR", p.TLSDir) }
func (e nodeEnv) caDir(p Paths) string  { return e.getOr("SB_CLUSTER_CA_DIR", p.CADir) }
func (e nodeEnv) raftDir(p Paths) string {
	return e.getOr("SB_RAFT_DATA_DIR", p.RaftDir)
}

// publicAPIURL is the URL an operator's laptop uses, as install.sh prints
// it: https://<domain> in domain mode, else http://<public host>:<port>.
func (e nodeEnv) publicAPIURL(advertise string) string {
	if d := e.get("SB_DOMAIN"); d != "" {
		return "https://" + d
	}
	host := e.getOr("SB_PUBLIC_HOST", advertise)
	return "http://" + net.JoinHostPort(host, e.apiPort())
}

// nodeRoles splits an SB_NODE_ROLE value; "" and "mixed" are every role.
func nodeRoles(raw string) (map[string]bool, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" || raw == "mixed" {
		return map[string]bool{"server": true, "worker": true, "ingress": true}, nil
	}
	out := map[string]bool{}
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		switch part {
		case "server", "worker", "ingress":
			out[part] = true
		case "mixed":
			return nil, fmt.Errorf("role %q: mixed is server,worker,ingress and can't be combined", raw)
		default:
			return nil, fmt.Errorf("role %q: each part must be server, worker or ingress", raw)
		}
	}
	return out, nil
}

// joinRoleOf is the join role (what a token admits) for an SB_NODE_ROLE:
// any set with server is a server; else worker beats ingress. The same rule
// as the cluster's adopt (joinRoleForNodeRole).
func joinRoleOf(nodeRole string) (string, error) {
	roles, err := nodeRoles(nodeRole)
	if err != nil {
		return "", err
	}
	switch {
	case roles["server"]:
		return cluster.JoinRoleServer, nil
	case roles["worker"]:
		return cluster.JoinRoleWorker, nil
	default:
		return cluster.JoinRoleIngress, nil
	}
}

// pickNodeID is --node-id, else the short host name.
func pickNodeID(h Host, asked string) (string, error) {
	id := strings.TrimSpace(asked)
	if id == "" {
		name, err := h.Hostname()
		if err != nil {
			return "", fmt.Errorf("read the host name: %w; pass --node-id", err)
		}
		id = name
	}
	if !cluster.ValidJoinNodeID(id) {
		return "", fmt.Errorf("node ID %q: use 1-63 letters, digits, '.', '_' or '-', starting with a letter or digit (--node-id)", id)
	}
	return id, nil
}

// pickAdvertise is --advertise, else the default route's source address.
func pickAdvertise(h Host, asked string) (string, error) {
	if ip := strings.TrimSpace(asked); ip != "" {
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("--advertise %q is not an IP address", ip)
		}
		return ip, nil
	}
	ip, err := h.PrimaryIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", errors.New("could not find this machine's address; pass --advertise")
	}
	return ip, nil
}

// clusterEnvHeader starts a cluster.env this package writes.
const clusterEnvHeader = "# Managed by sandboxd init / sandboxd join. Layered on top of\n" +
	"# /etc/sandboxd/sandboxd.env by the systemd drop-in\n" +
	"# /etc/systemd/system/sandboxd.service.d/cluster.conf.\n"

// addressSettings are the cluster.env lines both init and join write: the
// same names and defaults as cluster-init.sh and cluster-join.sh.
func addressSettings(set *envSet, nodeID, advertise string, env nodeEnv, p Paths, o AddressOptions) {
	set.set("SB_ENABLE_CLUSTER", "true")
	set.set("SB_NODE_ID", nodeID)
	apiURL := o.APIAdvertiseURL
	if apiURL == "" {
		apiURL = "http://" + net.JoinHostPort(advertise, env.apiPort())
	}
	set.set("SB_API_ADVERTISE_URL", apiURL)
	dataPlane := o.DataPlaneAdvertiseHost
	if dataPlane == "" {
		dataPlane = advertise
	}
	set.set("SB_DATA_PLANE_ADVERTISE_HOST", dataPlane)
	set.set("SB_RAFT_BIND_ADDR", raftBind)
	set.set("SB_RAFT_ADVERTISE_ADDR", net.JoinHostPort(advertise, "7000"))
	set.set("SB_RAFT_DATA_DIR", env.raftDir(p))
	set.set("SB_CLUSTER_TLS_DIR", env.tlsDir(p))
	set.set("SB_GOSSIP_BIND_ADDR", gossipBind)
	set.set("SB_GOSSIP_ADVERTISE_ADDR", net.JoinHostPort(advertise, "7001"))
	set.set("SB_CLUSTER_INTERNAL_LISTEN", internalBind)
	set.set("SB_CLUSTER_INTERNAL_ADVERTISE", "https://"+net.JoinHostPort(advertise, "7002"))
	set.set("SB_CLUSTER_MAX_AUTO_VOTERS", defaultMaxAutoVoters)
	if o.NodeRole != "" {
		set.set("SB_NODE_ROLE", o.NodeRole)
	}
	if ingress := ingressHostFor(env, o.IngressAdvertiseHost); ingress != "" {
		set.set("SB_INGRESS_ADVERTISE_HOST", ingress)
	}
}

// ingressHostFor is SB_INGRESS_ADVERTISE_HOST for cluster.env: the flag;
// else nothing when sandboxd.env already sets it (cluster.env would win
// over the operator's choice); else what an earlier init or join wrote;
// else the domain. Terraform passes --ingress-advertise-host <domain> to
// every node, so a node added by hand defaults to the same: the cluster's
// address for its custom-domain DNS answer, instead of each node's IP.
func ingressHostFor(env nodeEnv, flag string) string {
	if flag != "" {
		return flag
	}
	if strings.TrimSpace(env.base["SB_INGRESS_ADVERTISE_HOST"]) != "" {
		return ""
	}
	if h := strings.TrimSpace(env.cluster["SB_INGRESS_ADVERTISE_HOST"]); h != "" {
		return h
	}
	return strings.TrimSpace(env.base["SB_DOMAIN"])
}

// AddressOptions are the optional address settings init and join share
// (the scripts' flags of the same names).
type AddressOptions struct {
	NodeRole               string
	APIAdvertiseURL        string
	DataPlaneAdvertiseHost string
	IngressAdvertiseHost   string
}
