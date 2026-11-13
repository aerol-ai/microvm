package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/nodejoin"
	"github.com/aerol-ai/microvm/internal/version"
)

// The node commands of one-line joins (plans/kubectl-style-cluster-ops.md
// §3.1, §4): init, join, preflight, adopt, reset and join-command. Like upgrade, none of
// them falls through to the daemon: each acts on the node from outside it
// and talks to the running sandboxd over its API. The work is in
// internal/nodejoin; this file is the command line.
const (
	initSubcommand      = "init"
	joinSubcommand      = "join"
	preflightSubcommand = "preflight"
	adoptSubcommand     = "adopt"
	resetSubcommand     = "reset"
	tokenSubcommand     = "join-command"
)

// isNodeCommand reports whether arg is one of them.
func isNodeCommand(arg string) bool {
	switch arg {
	case initSubcommand, joinSubcommand, preflightSubcommand, adoptSubcommand, resetSubcommand, tokenSubcommand:
		return true
	}
	return false
}

// Seams for tests: the machine and the API the commands act on.
var (
	newNodeHost  = func() nodejoin.Host { return nodejoin.SystemHost{} }
	nodePaths    = nodejoin.DefaultPaths
	nodeLocalAPI = ""
	nodeKeyTool  = func(_ context.Context, args []string, out io.Writer) error { return runKeyCLI(args, out) }
)

const initUsage = `usage: sudo sandboxd init [--role <role>] [--token <role>=<id.secret>[:<ttl>]]...
                          [--advertise <ip>] [--node-id <id>] [--key-custody file|wrapped]

Starts a cluster on this machine, which becomes its first server: makes the
cluster CA, the gossip key and the server key (or wraps it, under wrapped
custody), signs this node's cert, writes cluster.env and restarts sandboxd
in cluster mode. Then it registers the join tokens, writes
/etc/sandboxd/admin-context.json (0600) for ` + "`aerolvm config import`" + ` and prints
a join command and a login line. Run install.sh first. Safe to run again.

  --role <role>               SB_NODE_ROLE: must include server, or be mixed
                              (the default, as cluster-init.sh)
  --token <role>=<t>[:<ttl>]  register a join token made elsewhere (repeatable);
                              ttl like 2h, 0 for never (worker and ingress only);
                              each is reusable. With none, init makes a 2h
                              worker token.
  --advertise <ip>            the address other nodes reach this one on
                              (default: the default route's source address)
  --node-id <id>              default: the short host name
  --key-custody file|wrapped  default: SB_CREDENTIAL_KEY_CUSTODY, else file
  --gossip-key <base64>       default: a new random key
  --api-advertise-url <url>, --data-plane-advertise-host <h>,
  --ingress-advertise-host <h>
                              as cluster-init.sh's flags of the same names
  --installer-url <url>       the installer the printed join command fetches
  --wait-timeout <dur>        how long to wait for sandboxd to lead (default 3m)
  --files-only                write the cluster's files and stop: no root,
                              no systemd, no restart (a Kubernetes init
                              container); run init again once sandboxd is
                              up to admit this node and make join tokens
  --external-ca               with --files-only: start an external-CA
                              cluster; the TLS dir already holds the bank's
                              CA and this node's cert-manager certificate
                              (aerolvm-role:server), so no CA is made
`

const joinUsage = `usage: sudo sandboxd join <url> --token <id.secret> [--ca-cert-hash sha256:<hex>]
                          [--node-id <id>] [--advertise <ip>] [--role <role>]

Joins this machine to the cluster behind <url> (https://<server>:7003). The
token decides the role. It checks the cluster (the CA hash, or the token's
proof when there is no hash) and this machine first, and stops before
writing anything if a check fails. Then it makes a key, gets it signed,
writes the certs and cluster.env, restarts sandboxd and waits until this
node is a member. Run it again after a failure: the same key gets the same
answer.

  --token <id.secret>         the join token (aerolvm join-command makes one)
  --ca-cert-hash sha256:<hex> pin the cluster CA
  --node-id <id>              default: the short host name
  --advertise <ip>            default: the default route's source address
  --role <role>               SB_NODE_ROLE, when it should be more than the
                              token's role (mixed, or server,worker)
  --api-advertise-url <url>, --data-plane-advertise-host <h>,
  --ingress-advertise-host <h>
                              as cluster-join.sh's flags of the same names
  --wait-timeout <dur>        how long to wait to be a member (default 3m)
  --by-certificate            external-CA mode: join with the certificate
                              already in the TLS dir (ca.crt, node.crt and
                              node.key, from cert-manager); no token. The
                              node ID and role are the certificate's
  --files-only                write this node's files and stop: no root,
                              no systemd, no restart (a Kubernetes init
                              container); sandboxd joins as it starts
`

const preflightUsage = `usage: sandboxd preflight [--join <url> --token <id.secret>] [--ca-cert-hash sha256:<hex>]
                          [--role server|worker|ingress] [--node-id <id>] [-o text|json]
       sandboxd preflight --pod [--kvm] [-o text|json]

Checks this machine, and with --join the network to the cluster, before init
or join changes anything; prints a fix for each failure. With --join the
join server dials this machine back on the ports its role needs.

--pod checks the machine a Kubernetes worker pod landed on (its preflight
init container): cgroup v2, the kernel version and br_netfilter, and with
--kvm /dev/kvm. Its last line names every failure, for the operator.
Exit status: 0 when nothing failed, 1 when a check failed, 2 for a usage error.
`

const adoptUsage = `usage: sudo sandboxd adopt [--ca-key <file>]

Brings a cluster built with cluster-init.sh onto one-line joins and cert
renewal (plans/kubectl-style-cluster-ops.md §4.4). Run it on the seed first
(it imports /etc/sandboxd/cluster-ca/ca.key), then on every other server
(each fetches the CA key from the seed over mTLS). Workers and ingress nodes
need nothing. Safe to run again.

  --ca-key <file>   a saved copy of the seed's ca.key, when the seed is gone
`

const tokenUsage = `usage: sudo sandboxd join-command [--role worker|ingress|server|mixed] [--ttl 2h]
                          [--reusable] [--json] [--installer-url <url>]

Run on a server: makes a join token through this server's own API and prints
the line that adds a machine with it, like kubeadm's
` + "`kubeadm token create --print-join-command`" + ` on a control-plane node. Run
the line on the new machine, as printed. The token decides the role. With a
domain, the line also carries this node's --domain and DNS options; it reads
the Cloudflare API token from $CLOUDFLARE_API_TOKEN on the new machine.

A server token can only be made on a server: the cluster refuses one asked
through a worker or an ingress node, and ` + "`aerolvm join-command`" + ` from a laptop
goes through the ingress. So use this for a server added later, for example
with Terraform's node_join_tokens (--json prints the token in "token").

  --role ROLE       worker (default), ingress or server; or mixed, or a list
                    such as server,worker: a server token, and the line adds
                    --role so the node also runs sandboxes or takes traffic
  --ttl DURATION    like 30m, 2h or 24h (2h by default; server tokens at most
                    24h); 0 for never, worker and ingress only
  --reusable        let many machines join with the same token
  --json            print the token object and "command" instead of the line
  --installer-url   the installer the printed line fetches

Stdout is only the line (or the JSON); notes go to stderr.
`

const resetUsage = `usage: sudo sandboxd reset --yes

Takes this machine out of its cluster: asks the cluster to delete this node
(when it can reach it), stops sandboxd and removes cluster.env, the certs and
keys, the CA store and the Raft data. The database, the server key and
sandboxd.env stay. Then join again, or start sandboxd as a single node.
`

// nodeFlags holds every node command's flags; each command registers its own.
type nodeFlags struct {
	nodeID, advertise, role           string
	apiURL, dataPlane, ingressHost    string
	waitTimeout                       time.Duration
	token, caHash, installer, custody string
	gossipKey                         string
	tokens                            stringList
	output                            string
	joinURL                           string
	caKey                             string
	yes                               bool
	ttl                               string
	reusable, json                    bool
	filesOnly                         bool
	pod, kvm                          bool
	byCert                            bool
	externalCA                        bool
}

func (f *nodeFlags) address() nodejoin.AddressOptions {
	return nodejoin.AddressOptions{NodeRole: f.role, APIAdvertiseURL: f.apiURL, DataPlaneAdvertiseHost: f.dataPlane, IngressAdvertiseHost: f.ingressHost}
}

// parseNodeArgs parses one node command's flags; flags may come before or
// after the positional arguments.
func parseNodeArgs(cmd string, args []string) (*nodeFlags, []string, error) {
	f := &nodeFlags{}
	fs := flag.NewFlagSet("sandboxd "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	switch cmd {
	case initSubcommand, joinSubcommand:
		fs.StringVar(&f.nodeID, "node-id", "", "")
		fs.StringVar(&f.advertise, "advertise", "", "")
		fs.StringVar(&f.role, "role", "", "")
		fs.StringVar(&f.apiURL, "api-advertise-url", "", "")
		fs.StringVar(&f.dataPlane, "data-plane-advertise-host", "", "")
		fs.StringVar(&f.ingressHost, "ingress-advertise-host", "", "")
		fs.DurationVar(&f.waitTimeout, "wait-timeout", 0, "")
		fs.BoolVar(&f.filesOnly, "files-only", false, "")
	case preflightSubcommand:
		fs.StringVar(&f.joinURL, "join", "", "")
		fs.StringVar(&f.token, "token", "", "")
		fs.StringVar(&f.caHash, "ca-cert-hash", "", "")
		fs.StringVar(&f.role, "role", "", "")
		fs.StringVar(&f.nodeID, "node-id", "", "")
		fs.StringVar(&f.output, "o", "text", "")
		fs.StringVar(&f.output, "output", "text", "")
		fs.BoolVar(&f.pod, "pod", false, "")
		fs.BoolVar(&f.kvm, "kvm", false, "")
	case adoptSubcommand:
		fs.StringVar(&f.caKey, "ca-key", "", "")
	case resetSubcommand:
		fs.BoolVar(&f.yes, "yes", false, "")
		fs.BoolVar(&f.yes, "y", false, "")
	case tokenSubcommand:
		fs.StringVar(&f.role, "role", "worker", "")
		fs.StringVar(&f.ttl, "ttl", "", "")
		fs.BoolVar(&f.reusable, "reusable", false, "")
		fs.BoolVar(&f.json, "json", false, "")
		fs.StringVar(&f.installer, "installer-url", "", "")
	}
	switch cmd {
	case initSubcommand:
		fs.Var(&f.tokens, "token", "")
		fs.BoolVar(&f.externalCA, "external-ca", false, "")
		fs.StringVar(&f.custody, "key-custody", "", "")
		fs.StringVar(&f.gossipKey, "gossip-key", "", "")
		fs.StringVar(&f.installer, "installer-url", "", "")
	case joinSubcommand:
		fs.StringVar(&f.token, "token", "", "")
		fs.StringVar(&f.caHash, "ca-cert-hash", "", "")
		fs.BoolVar(&f.byCert, "by-certificate", false, "")
	}
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	return f, positional, nil
}

// runNodeCLI runs one node command and returns the exit status.
func runNodeCLI(cmd string, args []string, stdout, stderr io.Writer) int {
	usage := map[string]string{
		initSubcommand: initUsage, joinSubcommand: joinUsage, preflightSubcommand: preflightUsage,
		adoptSubcommand: adoptUsage, resetSubcommand: resetUsage, tokenSubcommand: tokenUsage,
	}[cmd]
	f, positional, err := parseNodeArgs(cmd, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd %s: %v\n%s", cmd, err, usage)
		return 2
	}
	wantArgs := 0
	if cmd == joinSubcommand {
		wantArgs = 1
	}
	if len(positional) != wantArgs {
		msg := fmt.Sprintf("unexpected argument %q", strings.Join(positional, " "))
		if wantArgs == 1 && len(positional) == 0 {
			msg = "missing the join URL (https://<server>:7003)"
		}
		fmt.Fprintf(stderr, "sandboxd %s: %s\n%s", cmd, msg, usage)
		return 2
	}
	ctx, cancel := signalContext()
	defer cancel()
	host := newNodeHost()
	paths := nodePaths()
	printer := nodejoin.Printer{Out: stdout}
	switch cmd {
	case preflightSubcommand:
		return runPreflight(ctx, f, host, paths, stdout, stderr, usage)
	case initSubcommand:
		var specs []nodejoin.TokenSpec
		for _, raw := range f.tokens {
			spec, err := nodejoin.ParseTokenSpec(raw)
			if err != nil {
				fmt.Fprintf(stderr, "sandboxd init: %v\n", err)
				return 2
			}
			specs = append(specs, spec)
		}
		in := &nodejoin.Initer{Paths: paths, Host: host, Version: version.Version, Printer: printer, LocalAPI: nodeLocalAPI,
			KeyTool: func(ctx context.Context, args []string) error { return nodeKeyTool(ctx, args, stdout) }}
		_, err = in.Run(ctx, nodejoin.InitOptions{
			NodeID: f.nodeID, Advertise: f.advertise, Address: f.address(), Tokens: specs, KeyCustody: f.custody,
			GossipKey: f.gossipKey, WaitTimeout: f.waitTimeout, InstallerURL: f.installer, FilesOnly: f.filesOnly,
			ExternalCA: f.externalCA,
		})
	case joinSubcommand:
		// --by-certificate (external-CA mode) joins with the certificate in
		// the TLS dir instead of a token.
		if strings.TrimSpace(f.token) == "" && !f.byCert {
			fmt.Fprintf(stderr, "sandboxd join: --token is required (or --by-certificate in external-CA mode)\n%s", usage)
			return 2
		}
		j := &nodejoin.Joiner{Paths: paths, Host: host, Version: version.Version, Printer: printer, LocalAPI: nodeLocalAPI}
		_, err = j.Run(ctx, nodejoin.JoinOptions{
			URL: positional[0], Token: f.token, CACertHash: f.caHash, NodeID: f.nodeID, Advertise: f.advertise,
			Address: f.address(), WaitTimeout: f.waitTimeout, FilesOnly: f.filesOnly, ByCertificate: f.byCert,
		})
	case adoptSubcommand:
		a := &nodejoin.Adopter{Paths: paths, Host: host, Printer: printer, LocalAPI: nodeLocalAPI}
		_, err = a.Run(ctx, nodejoin.AdoptOptions{CAKeyFile: f.caKey})
	case tokenSubcommand:
		m := &nodejoin.TokenMaker{Paths: paths, Host: host, Printer: nodejoin.Printer{Out: stderr}, LocalAPI: nodeLocalAPI}
		var res nodejoin.TokenResult
		if res, err = m.Run(ctx, nodejoin.TokenOptions{Role: f.role, TTL: f.ttl, Reusable: f.reusable, InstallerURL: f.installer}); err == nil {
			if f.json {
				raw, _ := json.MarshalIndent(res, "", "  ")
				fmt.Fprintln(stdout, string(raw))
			} else {
				fmt.Fprintln(stdout, res.Command)
			}
		}
	case resetSubcommand:
		r := &nodejoin.Resetter{Paths: paths, Host: host, Printer: printer, LocalAPI: nodeLocalAPI}
		err = r.Run(ctx, nodejoin.ResetOptions{Yes: f.yes})
		if errors.Is(err, nodejoin.ErrResetNeedsYes) {
			fmt.Fprintf(stderr, "sandboxd reset: %v\n%s", err, usage)
			return 2
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func runPreflight(ctx context.Context, f *nodeFlags, host nodejoin.Host, paths nodejoin.Paths, stdout, stderr io.Writer, usage string) int {
	if f.output != "text" && f.output != "json" {
		fmt.Fprintf(stderr, "sandboxd preflight: -o must be text or json, got %q\n%s", f.output, usage)
		return 2
	}
	if (f.joinURL == "") != (f.token == "") {
		fmt.Fprintf(stderr, "sandboxd preflight: --join and --token go together\n%s", usage)
		return 2
	}
	if f.kvm && !f.pod {
		fmt.Fprintf(stderr, "sandboxd preflight: --kvm goes with --pod\n%s", usage)
		return 2
	}
	if f.pod {
		if f.joinURL != "" {
			fmt.Fprintf(stderr, "sandboxd preflight: --pod checks this machine only; leave out --join\n%s", usage)
			return 2
		}
		report := nodejoin.PodPreflight(paths, f.kvm)
		if f.output == "json" {
			report.PrintJSON(stdout)
		} else {
			report.Print(stdout)
			report.PrintPodSummary(stdout)
		}
		if !report.OK() {
			return 1
		}
		return 0
	}
	pf := &nodejoin.Preflighter{Paths: paths, Host: host, Version: version.Version}
	report, err := pf.Run(ctx, nodejoin.PreflightOptions{
		JoinURL: f.joinURL, Token: f.token, CACertHash: f.caHash, Role: f.role, NodeID: f.nodeID,
	})
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd preflight: %v\n", err)
		return 2
	}
	if f.output == "json" {
		report.PrintJSON(stdout)
	} else {
		report.Print(stdout)
	}
	if !report.OK() {
		return 1
	}
	return 0
}
