package nodejoin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// TokenMaker is `sandboxd join-command`: it makes a join token through this
// server's own API and prints the line that joins a machine with it, as
// kubeadm's `kubeadm token create --print-join-command` does on a
// control-plane node.
//
// A server token can only be made on a server: the cluster refuses one asked
// by a worker or an ingress node (kops 14/17, J1), and a laptop whose API URL
// is the domain reaches the cluster through the ingress. So `aerolvm
// join-command --role server` from a laptop is refused once an ingress
// fronts the API, and this is the way to get a fresh server token for a
// server added after the module's 24-hour one (node_join_tokens).
type TokenMaker struct {
	Paths    Paths
	Host     Host
	Printer  Printer
	LocalAPI string
}

// ErrJoinCommandNotOnServer is join-command run on a worker or ingress node.
var ErrJoinCommandNotOnServer = errors.New("sandboxd join-command runs on a server: the cluster makes join tokens only for a server's own request")

// TokenOptions are join-command's flags.
type TokenOptions struct {
	Role         string // worker (default), ingress or server
	TTL          string // like 2h; 0 never expires (worker and ingress only); "" is the cluster's default
	Reusable     bool
	InstallerURL string
}

// TokenResult is the token and the line that uses it.
type TokenResult struct {
	cluster.JoinTokenCreated
	Command string `json:"command"`
}

// Run makes the token. The caller prints Command (text) or the whole result
// (JSON); Run prints only a note about the token's life on the Printer.
func (m *TokenMaker) Run(ctx context.Context, o TokenOptions) (TokenResult, error) {
	if !m.Host.IsRoot() {
		return TokenResult{}, errors.New("run sandboxd join-command as root (sudo): it reads the operator token from sandboxd.env")
	}
	role := strings.ToLower(strings.TrimSpace(o.Role))
	if role == "" {
		role = cluster.JoinRoleWorker
	}
	if !cluster.ValidJoinRole(role) {
		return TokenResult{}, fmt.Errorf("--role must be worker, ingress or server, got %q", o.Role)
	}
	env, err := loadNodeEnv(m.Paths)
	if err != nil {
		return TokenResult{}, err
	}
	if !env.clusterMode() {
		return TokenResult{}, errors.New("this node is not in a cluster (no SB_ENABLE_CLUSTER=true in cluster.env): start one with `sandboxd init`")
	}
	if own, err := joinRoleOf(env.get("SB_NODE_ROLE")); err != nil {
		return TokenResult{}, err
	} else if own != cluster.JoinRoleServer {
		return TokenResult{}, ErrJoinCommandNotOnServer
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	created, err := env.localAPI(m.LocalAPI).createToken(ctx, cluster.JoinTokenCreateRequest{
		Role: role, TTL: strings.TrimSpace(o.TTL), Reusable: o.Reusable,
		CreatedBy: "sandboxd join-command on " + env.get("SB_NODE_ID"),
	})
	if err != nil {
		return TokenResult{}, err
	}
	if len(created.JoinURLs) == 0 {
		return TokenResult{}, errors.New("the cluster reported no join URL: no server has its join port (7003) open; check SB_CLUSTER_JOIN_LISTEN_ADDR on the servers")
	}
	installer := o.InstallerURL
	if installer == "" {
		installer = DefaultInstallerURL
	}
	life := "never expires"
	if created.ExpiresAt != nil {
		life = "expires at " + created.ExpiresAt.UTC().Format(time.RFC3339)
	}
	use := "works once"
	if created.Reusable {
		use = "works for any number of machines"
	}
	m.Printer.printf("sandboxd: %s token %s %s and %s; revoke it with: aerolvm delete jointoken %s\n", created.Role, created.ID, life, use, created.ID)
	if created.Warning != "" {
		m.Printer.printf("warning: %s\n", created.Warning)
	}
	return TokenResult{JoinTokenCreated: created, Command: JoinCommand(installer, created.JoinURLs[0], created.Token, created.CACertHash)}, nil
}
