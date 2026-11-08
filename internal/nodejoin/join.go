package nodejoin

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// JoinOptions is `sandboxd join <url> --token <t> …`.
type JoinOptions struct {
	URL        string
	Token      string
	CACertHash string
	NodeID     string
	Advertise  string
	Address    AddressOptions
	// WaitTimeout bounds the wait until the node is a member.
	WaitTimeout  time.Duration
	MinFreeBytes uint64
}

// Joiner runs a join on this machine.
type Joiner struct {
	Paths   Paths
	Host    Host
	Version string
	Printer
	// Client reaches the join port before the CA is known; nil is the
	// real one. LocalAPI is this node's API base; "" is loopback.
	Client   *http.Client
	LocalAPI string
}

// ErrPreflight is a join or init stopped by a failed check, before any
// file was written.
var ErrPreflight = errors.New("preflight failed; nothing was changed")

// DefaultWaitTimeout bounds init's leader wait and join's member wait.
const DefaultWaitTimeout = 3 * time.Minute

// JoinResult says what a join did.
type JoinResult struct {
	NodeID string
	Role   string
	Replay bool
	Voter  bool
}

// Run joins this machine to the cluster behind o.URL (§4): check the
// cluster and the machine, make the key and CSR, join, write the files,
// restart sandboxd and wait until this node is a member. A re-run after
// success keeps the node key, so the join server answers it as a replay
// and the files come out the same.
func (j *Joiner) Run(ctx context.Context, o JoinOptions) (JoinResult, error) {
	if !j.Host.IsRoot() {
		return JoinResult{}, errors.New("run sandboxd join as root (sudo)")
	}
	if err := installed(j.Paths); err != nil {
		return JoinResult{}, err
	}
	env, err := loadNodeEnv(j.Paths)
	if err != nil {
		return JoinResult{}, err
	}
	joinURL, err := normalizeJoinURL(o.URL)
	if err != nil {
		return JoinResult{}, err
	}
	if _, _, err := cluster.ParseJoinToken(o.Token); err != nil {
		return JoinResult{}, err
	}
	nodeID, err := pickNodeID(j.Host, o.NodeID)
	if err != nil {
		return JoinResult{}, err
	}
	advertise, err := pickAdvertise(j.Host, o.Advertise)
	if err != nil {
		return JoinResult{}, err
	}
	tlsDir := env.tlsDir(j.Paths)
	key, haveKey, err := loadNodeKey(tlsDir)
	if err != nil {
		return JoinResult{}, err
	}
	keyH := ""
	if haveKey {
		keyH = keyHash(key)
	}

	j.printf("[join] checking %s and this machine\n", joinURL)
	remote := remoteChecks(ctx, j.Host, remoteInput{
		joinURL: joinURL, token: o.Token, pin: o.CACertHash, nodeID: nodeID, keyHash: keyH,
		version: j.Version, client: j.Client,
	})
	role := remote.role
	var report Report
	minFree := o.MinFreeBytes
	if minFree == 0 {
		minFree = DefaultMinFreeBytes
	}
	if role != "" {
		report.add(localChecks(j.Host, j.Paths, env, rolePorts(role, false), minFree)...)
	}
	report.add(remote.checks...)
	if remote.disc != nil {
		report.add(j.stateCheck(env, nodeID, remote.disc))
	}
	if role != "" {
		report.add(nodeRoleCheck(o.Address.NodeRole, role))
		report.add(custodyCheck(env))
	}
	report.Print(j.Out)
	if !report.OK() || remote.disc == nil || role == "" {
		return JoinResult{}, ErrPreflight
	}
	d := remote.disc

	// The key is written before the join call and kept whatever happens
	// next: a single-use token is bound to it, so a re-run after a crash
	// must present the same key to get the same answer.
	if !haveKey {
		k, keyPEM, err := cluster.NewNodeKey()
		if err != nil {
			return JoinResult{}, err
		}
		if err := os.MkdirAll(tlsDir, 0o700); err != nil {
			return JoinResult{}, err
		}
		if err := cluster.WriteFileAtomic(nodeKeyFile(tlsDir), keyPEM, 0o600); err != nil {
			return JoinResult{}, err
		}
		key = k
	}
	resp, err := j.join(ctx, d, o.Token, nodeID, role, key)
	if err != nil {
		return JoinResult{}, err
	}
	if _, err := checkNodeCert([]byte(resp.NodeCert), d.ca, nodeID, key); err != nil {
		return JoinResult{}, fmt.Errorf("the join answer is not usable: %w", err)
	}
	if resp.CACert != d.info.CACert {
		return JoinResult{}, errors.New("the join answer names another CA than cluster-info did")
	}
	nodeRole := o.Address.NodeRole
	if nodeRole == "" {
		nodeRole = resp.Role
	}
	addr := o.Address
	addr.NodeRole = nodeRole

	journal := &fileJournal{}
	if err := j.writeJoinFiles(journal, env, resp, nodeID, advertise, joinURL, addr); err != nil {
		j.undo(journal, joinUndoNote)
		return JoinResult{}, err
	}
	if journal.changed() {
		j.printf("[join] files written; restarting sandboxd\n")
		if err := j.Host.DaemonReload(ctx); err != nil {
			j.undo(journal, joinUndoNote)
			return JoinResult{}, err
		}
		if err := j.Host.RestartSandboxd(ctx); err != nil {
			j.undo(journal, joinUndoNote)
			return JoinResult{}, fmt.Errorf("%w (see: systemctl status sandboxd; journalctl -u sandboxd)", err)
		}
	} else {
		j.printf("[join] every file is already as the cluster says; sandboxd keeps running\n")
	}
	// The files now name the token sandboxd takes from local tools.
	if written, err := loadNodeEnv(j.Paths); err == nil {
		env = written
	}
	api := env.localAPI(j.LocalAPI)
	timeout := o.WaitTimeout
	if timeout <= 0 {
		timeout = DefaultWaitTimeout
	}
	j.printf("[join] waiting until %s is a member (up to %s)\n", nodeID, timeout)
	m, err := api.waitForMember(ctx, nodeID, timeout)
	if err != nil {
		return JoinResult{}, fmt.Errorf("sandboxd restarted in cluster mode but %s did not show up as a member: %w (see: journalctl -u sandboxd)", nodeID, err)
	}
	res := JoinResult{NodeID: nodeID, Role: resp.Role, Replay: resp.Replay, Voter: m.Voter}
	again := ""
	if resp.Replay {
		again = " (already joined; nothing changed)"
	}
	j.printf("[join] %s joined the cluster as a %s node%s\n", nodeID, resp.Role, again)
	if resp.PATToken == "" && len(resp.PATSHA256) > 0 {
		j.printf("[join] it holds the operator token's hash, not the token: it checks the token by hash and calls its peers with its cert; its own SB_PAT_TOKEN works only for tools on this machine\n")
	}
	if resp.Role == cluster.JoinRoleServer && !m.Voter {
		j.printf("[join] it is not a Raft voter yet; the leader adds servers as voters up to the voter cap\n")
	}
	return res, nil
}

// join makes the CSR and calls POST /v1/join with the dial-back listeners
// open.
func (j *Joiner) join(ctx context.Context, d *discovery, token, nodeID, role string, key crypto.Signer) (cluster.JoinResponse, error) {
	csr, err := cluster.NewNodeCSR(key, nodeID)
	if err != nil {
		return cluster.JoinResponse{}, err
	}
	closeListeners, err := dialBackListeners(j.Host, rolePorts(role, false))
	if err != nil {
		return cluster.JoinResponse{}, err
	}
	defer closeListeners()
	j.printf("[join] joining as %s (%s)\n", nodeID, role)
	var resp cluster.JoinResponse
	err = postJoin(ctx, pinnedClient(d.pool), d.joinURL, cluster.JoinPath, cluster.JoinRequest{
		Token: token, NodeID: nodeID, Role: role, CSR: string(csr), Version: j.Version,
	}, &resp)
	var refusal *JoinRefusal
	if errors.As(err, &refusal) {
		if refusal.Reason == "dial_back" {
			j.printf("fix dial-back: %s\n", dialBackCheck(refusal.DialBack).Detail)
		}
		if fix := refusal.Fix(); fix != "" {
			j.printf("fix: %s\n", fix)
		}
	}
	return resp, err
}

// stateCheck refuses a machine that already holds another cluster's state:
// Raft data, or a cluster.env for another node or CA. The same node and
// CA is a re-run, which is fine.
func (j *Joiner) stateCheck(env nodeEnv, nodeID string, d *discovery) Check {
	c := Check{Name: "cluster state", Status: StatusOK, Detail: "this machine is in no cluster yet"}
	sameCA := false
	if raw, err := os.ReadFile(filepath.Join(env.tlsDir(j.Paths), "ca.crt")); err == nil {
		if ca, err := firstCert(raw); err == nil && cluster.CACertHash(ca) == d.info.ClusterID {
			sameCA = true
		}
	}
	rerun := env.clusterMode() && env.get("SB_NODE_ID") == nodeID && sameCA
	switch {
	case rerun:
		c.Detail = "already a member of this cluster as " + nodeID + " (a re-run)"
	case env.clusterMode() || dirHasEntries(env.raftDir(j.Paths)):
		c.Status = StatusFail
		c.Detail = "this machine already holds cluster state (cluster.env or " + env.raftDir(j.Paths) + ") for another node or cluster"
		c.Fix = "run `sudo sandboxd reset --yes` first"
	}
	return c
}

func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// nodeRoleCheck checks --role (an SB_NODE_ROLE) against the token's role:
// the cert and the admitted record carry the token's.
func nodeRoleCheck(nodeRole, tokenRole string) Check {
	c := Check{Name: "role", Status: StatusOK, Detail: "the token admits a " + tokenRole}
	if nodeRole == "" {
		return c
	}
	got, err := joinRoleOf(nodeRole)
	switch {
	case err != nil:
		c.Status, c.Detail, c.Fix = StatusFail, err.Error(), "use server, worker, ingress, mixed or a comma list of the first three"
	case got != tokenRole:
		c.Status, c.Detail = StatusFail, fmt.Sprintf("--role %s needs a %s token; this one admits a %s", nodeRole, got, tokenRole)
		c.Fix = "make a token for that role: aerolvm join-command --role " + got
	default:
		c.Detail = fmt.Sprintf("the token admits a %s; this node runs as %s", tokenRole, nodeRole)
	}
	return c
}

// custodyCheck: a cluster with wrapped custody sends only the wrapped key,
// which this node can open only through a key store set up by install.sh.
// The answer's custody is not known before the join, so this checks the
// node's own setting: wrapped custody needs a key store here.
func custodyCheck(env nodeEnv) Check {
	c := Check{Name: "key custody", Status: StatusOK, Detail: "file"}
	if !strings.EqualFold(env.get("SB_CREDENTIAL_KEY_CUSTODY"), secrets.CustodyWrapped) {
		return c
	}
	c.Detail = "wrapped, key store " + env.get("SB_SECRET_PROVIDER")
	if !secrets.IsExternalProvider(env.get("SB_SECRET_PROVIDER")) {
		c.Status, c.Detail = StatusFail, "wrapped custody with no key store (SB_SECRET_PROVIDER) in "+"sandboxd.env"
		c.Fix = "re-run the installer with --key-custody wrapped --secret-provider-env <file>"
	}
	return c
}

// writeJoinFiles writes everything the answer carries, through the journal.
func (j *Joiner) writeJoinFiles(jr *fileJournal, env nodeEnv, resp cluster.JoinResponse, nodeID, advertise, joinURL string, addr AddressOptions) error {
	tlsDir := env.tlsDir(j.Paths)
	if err := jr.write(filepath.Join(tlsDir, "ca.crt"), []byte(resp.CACert), 0o644); err != nil {
		return err
	}
	// A re-run gets a freshly signed cert for the same key. While the one on
	// disk is good and not yet due for renewal, keep it, so a re-run writes
	// nothing new and needs no restart.
	if !j.keepNodeCert(filepath.Join(tlsDir, "node.crt"), resp) {
		if err := jr.write(filepath.Join(tlsDir, "node.crt"), []byte(resp.NodeCert), 0o644); err != nil {
			return err
		}
	}
	// Servers hold the CA key (D5); the join server sent it only because
	// the token's role is server.
	if resp.CAKey != "" {
		if _, err := cluster.ParseClusterCA([]byte(resp.CACert), []byte(resp.CAKey)); err != nil {
			return fmt.Errorf("the CA key in the join answer: %w", err)
		}
		caDir := env.caDir(j.Paths)
		if err := jr.write(filepath.Join(caDir, "ca.crt"), []byte(resp.CACert), 0o644); err != nil {
			return err
		}
		if err := jr.write(filepath.Join(caDir, "ca.key"), []byte(resp.CAKey), 0o600); err != nil {
			return err
		}
	}
	var set envSet
	addressSettings(&set, nodeID, advertise, env, j.Paths, addr)
	set.set("SB_CLUSTER_BOOTSTRAP", "false")
	if resp.GossipKey != "" {
		set.set("SB_GOSSIP_SECRET_KEY", resp.GossipKey)
	}
	peers := strings.Join(resp.BootstrapPeers, ",")
	if peers == "" {
		// A server whose gossip view is empty still runs gossip itself.
		host, _, _ := net.SplitHostPort(strings.TrimPrefix(joinURL, "https://"))
		peers = net.JoinHostPort(host, "7001")
	}
	set.set("SB_BOOTSTRAP_PEERS", peers)
	if err := j.writeCredentials(jr, env, resp.Credentials, &set); err != nil {
		return err
	}
	patSettings(&set, resp)
	if err := jr.mergeEnv(j.Paths.ClusterEnv, clusterEnvHeader, set); err != nil {
		return err
	}
	// A server's answer carries the cluster's PAT, which replaces the
	// random one install.sh made; a worker or ingress node gets the PAT's
	// hashes instead and keeps (or gets) a token of its own (pat.go). It
	// lives in sandboxd.env, where install.sh reads it back on every re-run.
	pat, changed, err := joinPAT(env.base["SB_PAT_TOKEN"], resp)
	if err != nil {
		return err
	}
	if changed {
		var set envSet
		set.set("SB_PAT_TOKEN", pat)
		if err := jr.mergeEnv(j.Paths.EnvFile, "", set); err != nil {
			return err
		}
	}
	return jr.write(j.Paths.DropIn, []byte(dropInBody), 0o644)
}

// keepNodeCert reports whether the node.crt on disk can stay: it chains to
// the answer's CA, names the same node, carries the same key and role, and
// is not past two thirds of its life (when the renewer would replace it).
func (j *Joiner) keepNodeCert(path string, resp cluster.JoinResponse) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	ca, err := firstCert([]byte(resp.CACert))
	if err != nil {
		return false
	}
	old, err := checkNodeCert(raw, ca, resp.NodeID, nil)
	if err != nil {
		return false
	}
	fresh, err := firstCert([]byte(resp.NodeCert))
	if err != nil || cluster.CertKeyHash(old) != cluster.CertKeyHash(fresh) || cluster.ExtractPeerRole(old) != cluster.ExtractPeerRole(fresh) {
		return false
	}
	now := j.Host.Now()
	life := old.NotAfter.Sub(old.NotBefore)
	return now.Before(old.NotBefore.Add(life * 2 / 3))
}

// writeCredentials installs the cluster's server key the way cluster-join.sh
// does with its credential bundle.
func (j *Joiner) writeCredentials(jr *fileJournal, env nodeEnv, creds cluster.JoinCredentials, set *envSet) error {
	keyPath := env.credentialKeyPath()
	decode := func(what, v string) ([]byte, error) {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("the join answer's %s is not base64: %w", what, err)
		}
		return raw, nil
	}
	if creds.Custody == secrets.CustodyWrapped {
		if creds.Wrapped == "" {
			return errors.New("the cluster keeps its server key wrapped but sent no wrapped key")
		}
		if !secrets.IsExternalProvider(env.get("SB_SECRET_PROVIDER")) {
			return errors.New("the cluster keeps its server key wrapped, and this node has no key store to unwrap it: re-run the installer with --key-custody wrapped --secret-provider-env <file>")
		}
		raw, err := decode("wrapped key", creds.Wrapped)
		if err != nil {
			return err
		}
		if err := jr.write(env.wrappedKeyPath(), raw, 0o600); err != nil {
			return err
		}
		// The daemon refuses wrapped custody while a plaintext key file
		// exists; this node's own key sealed nothing the cluster needs.
		if err := jr.remove(keyPath); err != nil {
			return err
		}
		set.set("SB_CREDENTIAL_KEY_CUSTODY", secrets.CustodyWrapped)
		set.set("SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH", env.wrappedKeyPath())
		set.set("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", keyPath)
		set.set("SB_CREDENTIAL_ENCRYPTION_KEY", "")
		return nil
	}
	if creds.Key == "" {
		j.printf("[join] warning: the join server sent no server key; sealed credentials made elsewhere won't open on this node\n")
		return nil
	}
	raw, err := decode("server key", creds.Key)
	if err != nil {
		return err
	}
	value := strings.TrimSpace(string(raw))
	if k, err := base64.StdEncoding.DecodeString(value); err != nil || len(k) != 32 {
		return errors.New("the join answer's server key is not base64 of 32 bytes")
	}
	if err := jr.write(keyPath, raw, 0o600); err != nil {
		return err
	}
	if creds.KeyRing != "" {
		ring, err := decode("key ring", creds.KeyRing)
		if err != nil {
			return err
		}
		if err := jr.write(keyPath+".ring", ring, 0o600); err != nil {
			return err
		}
	}
	set.set("SB_CREDENTIAL_ENCRYPTION_KEY", value)
	set.set("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", keyPath)
	set.set("SB_CREDENTIAL_KEY_CUSTODY", "")
	return nil
}

// joinUndoNote ends join's rollback message.
const joinUndoNote = " (the node key stays, so a re-run with the same token still works)"

// undo rolls the journal back and says what it could not restore.
func (p *Printer) undo(jr *fileJournal, note string) {
	if failed := jr.rollback(); len(failed) > 0 {
		p.printf("could not put back: %s\n", strings.Join(failed, ", "))
		return
	}
	p.printf("put every file back as it was%s\n", note)
}
