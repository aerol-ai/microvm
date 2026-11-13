package nodejoin

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// init --external-ca (C23, plan §15.2.1): the seed server of a cluster whose
// certificates come from the bank's issuer. Its TLS dir is its pod's
// cert-manager Secret, so it writes cluster.env only: no CA made, no
// certificate signed, no join tokens (an external-CA cluster takes none).
//
//	TLS dir: ca.crt, node.crt (node:<id>, aerolvm-role:server), node.key
//	  ─► cluster.env: SB_CLUSTER_BOOTSTRAP=true, SB_CLUSTER_EXTERNAL_CA=true,
//	     the gossip key, the credential key
//	  ─► sandboxd starts and leads ─► the operator calls Adopt, which admits
//	     the seed by its own certificate

func (in *Initer) runExternalCA(ctx context.Context, o InitOptions) (InitResult, error) {
	if !o.FilesOnly {
		return InitResult{}, errors.New("--external-ca needs --files-only: an external-CA cluster runs on Kubernetes, where the operator starts sandboxd")
	}
	if len(o.Tokens) > 0 {
		return InitResult{}, errors.New("--external-ca takes no --token: nodes join by their certificates")
	}
	if err := installed(in.Paths); err != nil {
		return InitResult{}, err
	}
	env, err := loadNodeEnv(in.Paths)
	if err != nil {
		return InitResult{}, err
	}
	advertise, err := pickAdvertise(in.Host, o.Advertise)
	if err != nil {
		return InitResult{}, err
	}
	_, _, nodeID, role, err := externalCAIdentity(env.tlsDir(in.Paths))
	if err != nil {
		return InitResult{}, err
	}
	if o.NodeID != "" && o.NodeID != nodeID {
		return InitResult{}, fmt.Errorf("--node-id %s, but the certificate names %s", o.NodeID, nodeID)
	}
	if role != cluster.JoinRoleServer {
		return InitResult{}, fmt.Errorf("the certificate's role is %s; the first node holds Raft, so its certificate must say aerolvm-role:server", role)
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
	clusterID, err := externalClusterID(env.tlsDir(in.Paths))
	if err != nil {
		return InitResult{}, err
	}
	// A re-run on the seed it made changes nothing.
	if env.clusterMode() && strings.EqualFold(env.get("SB_CLUSTER_BOOTSTRAP"), "true") &&
		strings.EqualFold(env.get("SB_CLUSTER_EXTERNAL_CA"), "true") && env.get("SB_NODE_ID") == nodeID {
		in.printf("[init] this node's cluster files are already written; nothing to do\n")
		return InitResult{NodeID: nodeID, ClusterID: clusterID, Again: true}, nil
	}
	if env.clusterMode() {
		return InitResult{}, fmt.Errorf("%s already holds a cluster.env for another cluster or node; refusing to overwrite it", in.Paths.ClusterEnv)
	}
	gossipKey := o.GossipKey
	if gossipKey == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return InitResult{}, err
		}
		gossipKey = base64.StdEncoding.EncodeToString(raw)
	}
	journal := &fileJournal{}
	var set envSet
	addr := o.Address
	if addr.NodeRole == "" {
		addr.NodeRole = cluster.JoinRoleServer
	}
	addressSettings(&set, nodeID, advertise, env, in.Paths, addr)
	set.set("SB_CLUSTER_BOOTSTRAP", "true")
	set.set("SB_CLUSTER_EXTERNAL_CA", "true")
	set.set("SB_GOSSIP_SECRET_KEY", gossipKey)
	if err := in.seedCredentials(ctx, journal, env, custody, &set); err != nil {
		in.undo(journal, "")
		return InitResult{}, err
	}
	if err := journal.mergeEnv(in.Paths.ClusterEnv, clusterEnvHeader, set); err != nil {
		in.undo(journal, "")
		return InitResult{}, err
	}
	in.printf("[init] files written (--files-only, external CA). Start sandboxd with %s and %s in its environment; once it leads, the operator admits it by its certificate\n",
		in.Paths.EnvFile, in.Paths.ClusterEnv)
	return InitResult{NodeID: nodeID, ClusterID: clusterID}, nil
}

// externalClusterID names the cluster by the bank's CA, as the servers do
// (Cluster.externalCAClusterID): the first certificate in ca.crt.
func externalClusterID(tlsDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("ca.crt holds no certificate")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return cluster.CACertHash(ca), nil
}
