package nodejoin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// TokenSpec is one `--token <role>=<id.secret>[:<ttl>]`: a join token init
// registers as is (Terraform makes them with random_password).
type TokenSpec struct {
	Role  string
	Token string
	// TTL is a Go duration, "0" for never (worker and ingress only), or ""
	// for the default (2h).
	TTL string
}

// ParseTokenSpec reads one --token value.
func ParseTokenSpec(raw string) (TokenSpec, error) {
	role, rest, ok := strings.Cut(strings.TrimSpace(raw), "=")
	if !ok {
		return TokenSpec{}, fmt.Errorf("--token %q: want <role>=<id.secret>[:<ttl>]", raw)
	}
	spec := TokenSpec{Role: strings.ToLower(strings.TrimSpace(role))}
	spec.Token, spec.TTL, _ = strings.Cut(rest, ":")
	if !cluster.ValidJoinRole(spec.Role) {
		return TokenSpec{}, fmt.Errorf("--token %q: role must be server, worker or ingress", raw)
	}
	if _, _, err := cluster.ParseJoinToken(spec.Token); err != nil {
		return TokenSpec{}, fmt.Errorf("--token %s=…: %w", spec.Role, err)
	}
	if spec.TTL != "" && spec.TTL != "0" {
		d, err := time.ParseDuration(spec.TTL)
		if err != nil || d <= 0 {
			return TokenSpec{}, fmt.Errorf("--token %s=…: TTL %q is not a duration like 2h, or 0 for never", spec.Role, spec.TTL)
		}
		if spec.Role == cluster.JoinRoleServer && d > cluster.MaxServerJoinTTL {
			return TokenSpec{}, fmt.Errorf("--token server=…: server tokens last at most %s", cluster.MaxServerJoinTTL)
		}
	}
	if spec.Role == cluster.JoinRoleServer && spec.TTL == "0" {
		return TokenSpec{}, errors.New("--token server=…:0: server tokens must expire (at most 24h)")
	}
	return spec, nil
}

// JoinCommand is the one line a new machine runs (§3.1).
func JoinCommand(installer, joinURL, token, caHash string) string {
	if installer == "" {
		installer = DefaultInstallerURL
	}
	line := fmt.Sprintf("curl -fsSL %s | sudo bash -s -- join %s --token %s", installer, joinURL, token)
	if caHash != "" {
		line += " --ca-cert-hash " + caHash
	}
	return line
}

// InitOptions is `sandboxd init`.
type InitOptions struct {
	NodeID    string
	Advertise string
	Address   AddressOptions
	Tokens    []TokenSpec
	// KeyCustody is file or wrapped; "" reads SB_CREDENTIAL_KEY_CUSTODY.
	KeyCustody string
	// GossipKey is base64 of 16, 24 or 32 bytes; "" makes one.
	GossipKey    string
	WaitTimeout  time.Duration
	MinFreeBytes uint64
	InstallerURL string
}

// Initer starts a cluster on this machine.
type Initer struct {
	Paths   Paths
	Host    Host
	Version string
	Printer
	// KeyTool runs `sandboxd key <args>` in-process (wrapped custody).
	KeyTool  func(ctx context.Context, args []string) error
	LocalAPI string
}

// InitResult says what init did.
type InitResult struct {
	NodeID     string
	ClusterID  string
	Again      bool
	JoinURL    string
	APIURL     string
	JoinTokens []cluster.JoinTokenCreated
}

// Run does cluster-init.sh's job in Go (§4.1). A re-run on the seed it made
// changes no file and no key: it checks sandboxd leads, registers the
// tokens again (the cluster answers the stored rows) and prints the same.
func (in *Initer) Run(ctx context.Context, o InitOptions) (InitResult, error) {
	if !in.Host.IsRoot() {
		return InitResult{}, errors.New("run sandboxd init as root (sudo)")
	}
	if err := installed(in.Paths); err != nil {
		return InitResult{}, err
	}
	env, err := loadNodeEnv(in.Paths)
	if err != nil {
		return InitResult{}, err
	}
	nodeID, err := pickNodeID(in.Host, o.NodeID)
	if err != nil {
		return InitResult{}, err
	}
	advertise, err := pickAdvertise(in.Host, o.Advertise)
	if err != nil {
		return InitResult{}, err
	}
	if o.Address.NodeRole != "" {
		if r, err := joinRoleOf(o.Address.NodeRole); err != nil {
			return InitResult{}, err
		} else if r != cluster.JoinRoleServer {
			return InitResult{}, fmt.Errorf("--role %s can't start a cluster: the first node holds Raft, so its role must include server (or be mixed); join worker and ingress nodes with `sandboxd join`", o.Address.NodeRole)
		}
	}
	custody := strings.ToLower(strings.TrimSpace(o.KeyCustody))
	if custody == "" {
		custody = strings.ToLower(env.getOr("SB_CREDENTIAL_KEY_CUSTODY", secrets.CustodyFile))
	}
	if custody != secrets.CustodyFile && custody != secrets.CustodyWrapped {
		return InitResult{}, fmt.Errorf("--key-custody must be file or wrapped, got %q", custody)
	}
	if o.GossipKey != "" {
		if err := checkGossipKey(o.GossipKey); err != nil {
			return InitResult{}, err
		}
	}

	ca, again, state := in.seedState(env, nodeID)
	var report Report
	minFree := o.MinFreeBytes
	if minFree == 0 {
		minFree = DefaultMinFreeBytes
	}
	report.add(localChecks(in.Host, in.Paths, env, rolePorts(cluster.JoinRoleServer, true), minFree)...)
	report.add(state)
	report.Print(in.Out)
	if !report.OK() {
		return InitResult{}, ErrPreflight
	}

	if !again {
		journal := &fileJournal{}
		ca, err = in.writeSeed(ctx, journal, env, nodeID, advertise, custody, o)
		if err != nil {
			in.undo(journal, "")
			return InitResult{}, err
		}
		in.printf("[init] files written; restarting sandboxd in cluster mode\n")
		if err := in.Host.DaemonReload(ctx); err != nil {
			in.undo(journal, "")
			return InitResult{}, err
		}
		if err := in.Host.RestartSandboxd(ctx); err != nil {
			in.undo(journal, "")
			return InitResult{}, fmt.Errorf("%w (see: systemctl status sandboxd; journalctl -u sandboxd)", err)
		}
	} else {
		in.printf("[init] this node already started the cluster; checking it and registering the tokens again\n")
	}
	env, err = loadNodeEnv(in.Paths)
	if err != nil {
		return InitResult{}, err
	}
	api := env.localAPI(in.LocalAPI)
	timeout := o.WaitTimeout
	if timeout <= 0 {
		timeout = DefaultWaitTimeout
	}
	in.printf("[init] waiting until %s leads the cluster (up to %s)\n", nodeID, timeout)
	if err := api.waitForLeader(ctx, nodeID, timeout); err != nil {
		return InitResult{}, fmt.Errorf("sandboxd did not take the lead: %w (see: journalctl -u sandboxd)", err)
	}
	// Adopt admits this node's own key (renewal needs an admitted record)
	// with the CA it now holds; on a re-run it changes nothing.
	if _, err := api.adopt(ctx, cluster.AdoptRequest{}); err != nil {
		return InitResult{}, fmt.Errorf("record this node as admitted: %w", err)
	}

	res := InitResult{NodeID: nodeID, ClusterID: cluster.CACertHash(ca.Certificate()), Again: again,
		JoinURL: "https://" + net.JoinHostPort(advertise, fmt.Sprint(cluster.DefaultJoinPort)), APIURL: env.publicAPIURL(advertise)}
	tokens := o.Tokens
	if len(tokens) == 0 {
		// Like kubeadm init: one token, so the printed command works.
		tokens = []TokenSpec{{Role: cluster.JoinRoleWorker}}
	}
	for _, spec := range tokens {
		// Init's tokens join the first nodes, so each is reusable for its
		// TTL, like a kubeadm bootstrap token.
		created, err := api.createToken(ctx, cluster.JoinTokenCreateRequest{
			Role: spec.Role, TTL: spec.TTL, Reusable: true, Token: spec.Token,
		})
		if err != nil {
			return res, fmt.Errorf("register the %s join token: %w", spec.Role, err)
		}
		res.JoinTokens = append(res.JoinTokens, created)
	}
	if err := in.writeAdminContext(nodeID, res.APIURL, env.get("SB_PAT_TOKEN")); err != nil {
		return res, err
	}
	in.printSummary(res, o.InstallerURL)
	return res, nil
}

// seedState finds whether this machine is the seed init already made (a
// re-run) or holds some other cluster's state (refused).
func (in *Initer) seedState(env nodeEnv, nodeID string) (*cluster.ClusterCA, bool, Check) {
	c := Check{Name: "cluster state", Status: StatusOK, Detail: "this machine is in no cluster yet"}
	ca, err := cluster.LoadClusterCA(env.caDir(in.Paths))
	if err == nil && ca != nil && env.clusterMode() && strings.EqualFold(env.get("SB_CLUSTER_BOOTSTRAP"), "true") && env.get("SB_NODE_ID") == nodeID {
		if raw, err := os.ReadFile(filepath.Join(env.tlsDir(in.Paths), "ca.crt")); err == nil {
			if tlsCA, err := firstCert(raw); err == nil && cluster.CACertHash(tlsCA) == cluster.CACertHash(ca.Certificate()) {
				c.Detail = "this node already started the cluster " + shortHash(cluster.CACertHash(tlsCA))
				return ca, true, c
			}
		}
	}
	if env.clusterMode() || dirHasEntries(env.raftDir(in.Paths)) {
		c.Status = StatusFail
		c.Detail = "this machine already holds cluster state (cluster.env or " + env.raftDir(in.Paths) + ")"
		c.Fix = "run `sudo sandboxd reset --yes` first; on a cluster built with cluster-init.sh, run `sudo sandboxd adopt` instead"
	}
	return nil, false, c
}

// writeSeed makes the cluster's secrets and this node's cert and writes
// every file init owns.
func (in *Initer) writeSeed(ctx context.Context, jr *fileJournal, env nodeEnv, nodeID, advertise, custody string, o InitOptions) (*cluster.ClusterCA, error) {
	gossipKey := o.GossipKey
	if gossipKey == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		gossipKey = base64.StdEncoding.EncodeToString(raw)
	}
	var set envSet
	addressSettings(&set, nodeID, advertise, env, in.Paths, o.Address)
	set.set("SB_CLUSTER_BOOTSTRAP", "true")
	set.set("SB_GOSSIP_SECRET_KEY", gossipKey)
	if err := in.seedCredentials(ctx, jr, env, custody, &set); err != nil {
		return nil, err
	}

	now := in.Host.Now()
	caPEM, caKeyPEM, err := cluster.GenerateClusterCA("AerolVM Cluster CA", now)
	if err != nil {
		return nil, err
	}
	ca, err := cluster.ParseClusterCA(caPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}
	nodeKey, nodeKeyPEM, err := cluster.NewNodeKey()
	if err != nil {
		return nil, err
	}
	certPEM, _, err := ca.SignNodeCert(cluster.NodeCertRequest{
		PublicKey: nodeKey.Public(), NodeID: nodeID, Role: cluster.JoinRoleServer, Lifetime: seedCertTTL(env), Now: now,
	})
	if err != nil {
		return nil, err
	}
	caDir, tlsDir := env.caDir(in.Paths), env.tlsDir(in.Paths)
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{filepath.Join(caDir, "ca.crt"), ca.CertPEM(), 0o644},
		{filepath.Join(caDir, "ca.key"), ca.KeyPEM(), 0o600},
		{filepath.Join(tlsDir, "ca.crt"), ca.CertPEM(), 0o644},
		{filepath.Join(tlsDir, "node.key"), nodeKeyPEM, 0o600},
		{filepath.Join(tlsDir, "node.crt"), certPEM, 0o644},
	} {
		if err := jr.write(f.path, f.data, f.mode); err != nil {
			return nil, err
		}
	}
	if err := jr.mergeEnv(in.Paths.ClusterEnv, clusterEnvHeader, set); err != nil {
		return nil, err
	}
	if err := jr.write(in.Paths.DropIn, []byte(dropInBody), 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

// seedCertTTL is SB_CLUSTER_NODE_CERT_TTL when set and in range (the
// daemon's own bounds), else 90 days, so the seed's first cert lives as
// long as the ones its join service signs.
func seedCertTTL(env nodeEnv) time.Duration {
	if d, err := time.ParseDuration(env.get("SB_CLUSTER_NODE_CERT_TTL")); err == nil && d >= 5*time.Minute && d <= cluster.NodeCertLifetime {
		return d
	}
	return cluster.NodeCertLifetime
}

// seedCredentials makes or reuses the server key the way cluster-init.sh
// does: a plaintext key file, or, under wrapped custody, only the wrapped
// file (sandboxd key, in-process).
func (in *Initer) seedCredentials(ctx context.Context, jr *fileJournal, env nodeEnv, custody string, set *envSet) error {
	keyPath := env.credentialKeyPath()
	if custody == secrets.CustodyWrapped {
		if in.KeyTool == nil {
			return errors.New("wrapped custody needs the key tool")
		}
		if !secrets.IsExternalProvider(env.get("SB_SECRET_PROVIDER")) {
			return errors.New("--key-custody wrapped needs a key store: re-run the installer with --key-custody wrapped --secret-provider-env <file>")
		}
		wrapped := env.wrappedKeyPath()
		var err error
		switch {
		case fileExistsAt(wrapped):
			in.printf("[init] reusing the wrapped server key at %s\n", wrapped)
			err = in.KeyTool(ctx, []string{"verify"})
		case fileExistsAt(keyPath):
			in.printf("[init] wrapping the existing server key at %s\n", keyPath)
			if err = in.KeyTool(ctx, []string{"wrap"}); err == nil {
				err = jr.remove(keyPath)
			}
		default:
			err = in.KeyTool(ctx, []string{"wrap", "--generate", "--seed"})
		}
		if err != nil {
			return fmt.Errorf("server key: %w", err)
		}
		set.set("SB_CREDENTIAL_KEY_CUSTODY", secrets.CustodyWrapped)
		set.set("SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH", wrapped)
		set.set("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", keyPath)
		return nil
	}
	raw, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		raw = []byte(base64.StdEncoding.EncodeToString(key) + "\n")
		if err := jr.write(keyPath, raw, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	value := strings.TrimSpace(string(raw))
	if k, err := base64.StdEncoding.DecodeString(value); err != nil || len(k) != 32 {
		return fmt.Errorf("the server key at %s is not base64 of 32 bytes", keyPath)
	}
	set.set("SB_CREDENTIAL_ENCRYPTION_KEY", value)
	set.set("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", keyPath)
	return nil
}

func fileExistsAt(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// checkGossipKey is the daemon's rule: base64 of 16, 24 or 32 bytes.
func checkGossipKey(k string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
	if err != nil || (len(raw) != 16 && len(raw) != 24 && len(raw) != 32) {
		return errors.New("--gossip-key must be base64 of 16, 24 or 32 bytes")
	}
	return nil
}

// adminContext is the file `aerolvm config import` reads: one login.
type adminContext struct {
	Name   string `json:"name,omitempty"`
	APIURL string `json:"api_url"`
	Token  string `json:"token"`
}

// writeAdminContext writes admin-context.json (0600), kubeadm's admin.conf.
func (in *Initer) writeAdminContext(nodeID, apiURL, pat string) error {
	if pat == "" {
		return errors.New("sandboxd.env has no SB_PAT_TOKEN for the admin login")
	}
	raw, err := json.MarshalIndent(adminContext{Name: "aerolvm-" + nodeID, APIURL: apiURL, Token: pat}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(in.Paths.AdminContext), 0o755); err != nil {
		return err
	}
	return cluster.WriteFileAtomic(in.Paths.AdminContext, append(raw, '\n'), 0o600)
}

func (in *Initer) printSummary(res InitResult, installer string) {
	in.printf("\nThe cluster is up. This node, %s, is its first server and its leader.\n", res.NodeID)
	in.printf("Cluster ID (CA hash): %s\n", res.ClusterID)
	for _, t := range res.JoinTokens {
		life := "never expires"
		if t.ExpiresAt != nil {
			life = "valid until " + t.ExpiresAt.Format(time.RFC3339)
		}
		article := "a"
		if t.Role == cluster.JoinRoleIngress {
			article = "an"
		}
		in.printf("\nTo add %s %s node, run this on it (the token %s):\n\n  %s\n", article, t.Role, life, JoinCommand(installer, res.JoinURL, t.Token, res.ClusterID))
		if t.Warning != "" {
			in.printf("  warning: %s\n", t.Warning)
		}
	}
	in.printf("\nMake more join commands from your laptop with: aerolvm join-command --role worker\n")
	in.printf("\nTo use the cluster from your laptop, copy %s there (it holds the admin token; keep it private), then run:\n\n", in.Paths.AdminContext)
	in.printf("  aerolvm config import admin-context.json --use\n\nor log in to %s with: aerolvm login %s --token-stdin\n", res.APIURL, res.APIURL)
}
