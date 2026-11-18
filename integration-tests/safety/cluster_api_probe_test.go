package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cluster.sh up waits until every address the new cluster's API name
// resolves to has answered from this machine three rounds in a row, before
// its first kubectl or Helm call (bank-1's first run: one of two addresses
// never answered, and the Karpenter install timed out 17 minutes in). These
// run the real cluster.sh up against stubs: dig answers per round from a
// table, nc and kubectl answer per address between the rounds listed.

// apiProbe is one cluster.sh up run's world.
type apiProbe struct {
	// dns and dns6: "<from round> <address>..." lines, for A and AAAA; each
	// round uses the last line whose round has come.
	dns, dns6 string
	// tcp and api: "<address> <from round> [<until round>]" lines: nc
	// connects, and /version answers, through that address in those
	// rounds. An address not listed never does.
	tcp, api string
	// ip is this machine's address when up starts; later is the one it
	// learns again before the probe ("" = the same). cidr is the API's
	// allow-list ("" = ip/32).
	ip, later, cidr string
	wait, round     string
}

type apiProbeResult struct {
	code     int
	out, log string
}

func runClusterUp(t *testing.T, p apiProbe) apiProbeResult {
	t.Helper()
	needTools(t, "jq", "awk")
	root := t.TempDir()
	for _, f := range []string{"k8s/cluster.sh", "lib/common.sh", "lib/stage.sh"} {
		raw, err := os.ReadFile(filepath.Join(integrationDir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	world, bin := t.TempDir(), t.TempDir()
	log := filepath.Join(world, "calls.log")
	if p.ip == "" {
		p.ip = "203.0.113.7"
	}
	if p.later == "" {
		p.later = p.ip
	}
	if p.cidr == "" {
		p.cidr = p.ip + "/32"
	}
	if p.wait == "" {
		p.wait = "10"
	}
	if p.round == "" {
		p.round = "1"
	}
	for f, body := range map[string]string{"dns": p.dns, "dns6": p.dns6, "tcp": p.tcp, "api": p.api} {
		if err := os.WriteFile(filepath.Join(world, f), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// at <table> <address>: does the address answer in this round?
	at := `at() { set -- $(awk -v a="$2" '$1==a {print $2, $3}' "$STUB_DIR/$1"); r=$(cat "$STUB_DIR/round" 2>/dev/null || echo 0)
  [ -n "${1:-}" ] && [ "$r" -ge "$1" ] && { [ -z "${2:-}" ] || [ "$r" -le "$2" ]; }; }`
	// names <table>: the addresses a resolve in this round gives.
	names := `names() { awk -v r=$(cat "$STUB_DIR/round") 'NF && $1<=r {line=$0} END {n=split(line,a," "); for(i=2;i<=n;i++) print a[i]}' "$STUB_DIR/$1"; }`
	stubs := map[string]string{
		"aws": `echo "aws $*" >> "$STUB_LOG"
case "$*" in
  *"sts get-caller-identity"*) echo 111122223333 ;;
  *"eks update-kubeconfig"*) : ;;
  *"eks describe-cluster"*) printf '{"cluster":{"endpoint":"https://ABCD1234.yl4.us-east-1.eks.amazonaws.com","resourcesVpcConfig":{"publicAccessCidrs":["%s"]}}}\n' "$STUB_CIDR" ;;
  *) exit 1 ;;
esac`,
		"terraform": `echo "terraform $*" >> "$STUB_LOG"
case "$*" in *output*region*) echo us-east-1 ;; esac`,
		"curl": `echo "curl $*" >> "$STUB_LOG"
n=$(( $(cat "$STUB_DIR/curls" 2>/dev/null || echo 0) + 1 )); echo $n > "$STUB_DIR/curls"
[ "$n" = 1 ] && echo "$STUB_IP" || echo "$STUB_IP_LATER"`,
		// A round is one A resolve (the AAAA one follows it). A CNAME
		// line first, as dig prints one.
		"dig": names + `
echo "dig $*" >> "$STUB_LOG"
echo "api.elb.example."
case "$*" in
  *" A "*) r=$(( $(cat "$STUB_DIR/round" 2>/dev/null || echo 0) + 1 )); echo $r > "$STUB_DIR/round"; names dns ;;
  *" AAAA "*) names dns6 ;;
esac`,
		// macOS's nc: -h lists -G, which the probe must then use.
		"nc": at + `
[ "$1" = -h ] && { printf 'usage: nc\n\t-G conntimo\tConnection timeout in seconds\n' >&2; exit 1; }
echo "nc $*" >> "$STUB_LOG"
for a; do prev=$last; last=$a; done
at tcp "$prev"`,
		"kubectl": at + `
echo "kubectl $*" >> "$STUB_LOG"
addr=$(echo "$*" | sed -n 's#.*--server https://\[\{0,1\}\([0-9a-fA-F.:]*\)\]\{0,1\} .*#\1#p')
case "$*" in *"--tls-server-name ABCD1234.yl4.us-east-1.eks.amazonaws.com"*"get --raw /version"*) at api "$addr" ;; *) exit 1 ;; esac`,
		"helm": `case "$1" in version) echo v3.20.2+g8fb76d6; exit 0 ;; esac
echo "helm $*" >> "$STUB_LOG"`,
	}
	for n, b := range stubs {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"+b+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", filepath.Join(root, "k8s", "cluster.sh"), "up", "bank-1", "--karpenter", "--workers", "0")
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+log, "STUB_DIR="+world, "STUB_IP="+p.ip, "STUB_IP_LATER="+p.later, "STUB_CIDR="+p.cidr,
		"CLUSTER_API_WAIT="+p.wait, "CLUSTER_API_ROUND="+p.round, "HELM=helm", "TF_VAR_region=")
	out, _ := cmd.CombinedOutput()
	return apiProbeResult{code: cmd.ProcessState.ExitCode(), out: string(out), log: readLog(t, log)}
}

// helmInstalled reports whether up went on to the Karpenter install, and
// that it did so only after the last /version probe.
func helmInstalled(t *testing.T, r apiProbeResult) bool {
	t.Helper()
	h := strings.Index(r.log, "helm upgrade --install karpenter")
	if h < 0 {
		return false
	}
	if last := strings.LastIndex(r.log, "get --raw /version"); last > h {
		t.Errorf("a /version probe ran after the Karpenter install:\n%s", r.log)
	}
	return true
}

// wentOnAt checks up went on to the install after exactly round n.
func wentOnAt(t *testing.T, r apiProbeResult, n string, next string) {
	t.Helper()
	if r.code != 0 || !helmInstalled(t, r) {
		t.Fatalf("exit %d, want up to go on\n%s\n%s", r.code, r.out, r.log)
	}
	if !strings.Contains(r.out, "round "+n+": ") || !strings.Contains(r.out, "clean rounds in a row: 3 of 3") || strings.Contains(r.out, "round "+next+": ") {
		t.Errorf("up did not go on right after round %s:\n%s", n, r.out)
	}
}

// failedNaming checks up stopped with the message for addr, and no Helm call.
func failedNaming(t *testing.T, r apiProbeResult, addr string) {
	t.Helper()
	if r.code == 0 || !strings.Contains(r.out, "the cluster API address "+addr+" does not answer from this machine") ||
		helmInstalled(t, r) || strings.Contains(r.log, "helm ") {
		t.Fatalf("exit %d, want a failure naming %s and no Helm call\n%s\n%s", r.code, addr, r.out, r.log)
	}
}

func TestClusterUpWaitsForEveryAPIAddress(t *testing.T) {
	const a, b, c, v6 = "198.51.100.1", "198.51.100.2", "198.51.100.3", "2001:db8::1"
	t.Run("every address answers", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1\n" + b + " 1", api: a + " 1\n" + b + " 1"})
		wentOnAt(t, r, "3", "4")
		if !strings.Contains(r.out, "every cluster API address answers from this machine, 3 rounds in a row: "+a+" "+b) {
			t.Errorf("no success line:\n%s", r.out)
		}
		// The connect is bounded the macOS way, and /version goes through
		// each address with the run's kubeconfig and the API's own name.
		for _, want := range []string{"nc -z -G 5 -w 5 " + b + " 443",
			"--server https://" + b + " --tls-server-name ABCD1234.yl4.us-east-1.eks.amazonaws.com --request-timeout=10s get --raw /version",
			".state/bank-1/kubeconfig", "dig +short AAAA ABCD1234.yl4.us-east-1.eks.amazonaws.com"} {
			if !strings.Contains(r.log, want) {
				t.Errorf("no %q in the calls:\n%s", want, r.log)
			}
		}
		if !strings.Contains(r.out, "the cluster API allows this machine's address 203.0.113.7/32") {
			t.Errorf("the allowed range was not checked:\n%s", r.out)
		}
	})
	t.Run("one address never answers", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1", api: a + " 1", wait: "3"})
		failedNaming(t, r, b)
		if !strings.Contains(r.out, "(waited 3s") || !strings.Contains(r.out, "round 3: answers: "+a+"; does not answer: "+b+" (no TCP connect on 443); clean rounds in a row: 0 of 3") {
			t.Errorf("it did not keep trying, or did not log each round:\n%s", r.out)
		}
	})
	// Review of #1357: one clean round passed. Here round 1 gives only a;
	// the dead b comes from round 2 on.
	t.Run("a dead address absent from the first answer", func(t *testing.T) {
		failedNaming(t, runClusterUp(t, apiProbe{dns: "1 " + a + "\n2 " + a + " " + b, tcp: a + " 1", api: a + " 1"}), b)
	})
	t.Run("an address answers from round 3", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1\n" + b + " 3", api: a + " 1\n" + b + " 1"})
		wentOnAt(t, r, "5", "6")
		if !strings.Contains(r.out, "round 2: answers: "+a+"; does not answer: "+b) {
			t.Errorf("round 2 not logged as failing:\n%s", r.out)
		}
	})
	t.Run("a new address starts the count over", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + "\n3 " + a + " " + b, tcp: a + " 1\n" + b + " 1", api: a + " 1\n" + b + " 1"})
		wentOnAt(t, r, "5", "6")
		if !strings.Contains(r.out, "round 2: answers: "+a+"; does not answer: none; clean rounds in a row: 2 of 3") ||
			!strings.Contains(r.out, "round 3: answers: "+a+" "+b+"; does not answer: none; clean rounds in a row: 1 of 3") {
			t.Errorf("b's arrival did not restart the count:\n%s", r.out)
		}
	})
	t.Run("an address the name stops giving is still probed", func(t *testing.T) {
		// b answers in round 1 only and leaves the name in round 2: round 2
		// still probes it, fails, and starts over without it.
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b + "\n2 " + a, tcp: a + " 1\n" + b + " 1 1", api: a + " 1\n" + b + " 1"})
		wentOnAt(t, r, "5", "6")
		if !strings.Contains(r.out, "round 2: answers: "+a+"; does not answer: "+b+" (no TCP connect on 443)") {
			t.Errorf("round 2 did not probe b:\n%s", r.out)
		}
	})
	t.Run("a connect but no /version", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1\n" + b + " 1", api: a + " 1", wait: "3"})
		failedNaming(t, r, b)
		if !strings.Contains(r.out, b+" (no answer to /version)") {
			t.Errorf("the reason is not /version:\n%s", r.out)
		}
	})
	t.Run("the name is resolved again each round", func(t *testing.T) {
		// The dead address leaves the name on round 3, a live one joins.
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b + "\n3 " + a + " " + c, tcp: a + " 1\n" + c + " 1", api: a + " 1\n" + c + " 1"})
		wentOnAt(t, r, "5", "6")
		if !strings.Contains(r.out, "every cluster API address answers from this machine, 3 rounds in a row: "+a+" "+c) {
			t.Errorf("no success line for a and c:\n%s", r.out)
		}
	})
	t.Run("an IPv6 address is probed too", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a, dns6: "1 " + v6, tcp: a + " 1\n" + v6 + " 1", api: a + " 1\n" + v6 + " 1"})
		wentOnAt(t, r, "3", "4")
		for _, want := range []string{"nc -z -G 5 -w 5 " + v6 + " 443", "--server https://[" + v6 + "] --tls-server-name"} {
			if !strings.Contains(r.log, want) {
				t.Errorf("no %q in the calls:\n%s", want, r.log)
			}
		}
	})
	t.Run("an IPv6 address never answers", func(t *testing.T) {
		failedNaming(t, runClusterUp(t, apiProbe{dns: "1 " + a, dns6: "1 " + v6, tcp: a + " 1", api: a + " 1", wait: "3"}), v6)
	})
	t.Run("the wait ends before three clean rounds", func(t *testing.T) {
		// b joins in round 2 and answers, but the 2 s wait has no room for
		// three clean rounds after it.
		r := runClusterUp(t, apiProbe{dns: "1 " + a + "\n2 " + a + " " + b, tcp: a + " 1\n" + b + " 1", api: a + " 1\n" + b + " 1", wait: "2"})
		if r.code == 0 || !strings.Contains(r.out, "the cluster API did not answer 3 rounds in a row from this machine (waited 2s") || helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
	})
	t.Run("the name resolves to nothing", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "", wait: "3"})
		if r.code == 0 || !strings.Contains(r.out, "the cluster API name ABCD1234.yl4.us-east-1.eks.amazonaws.com resolves to no address from this machine") || helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
	})
	t.Run("this machine's address is no longer allowed", func(t *testing.T) {
		// At once: no round, no Helm call.
		r := runClusterUp(t, apiProbe{dns: "1 " + a, tcp: a + " 1", api: a + " 1", later: "203.0.113.9"})
		if r.code == 0 || !strings.Contains(r.out, "this machine's address is now 203.0.113.9/32, which the cluster API does not allow (it allows: 203.0.113.7/32); cluster.sh allow-ip bank-1 adds it") ||
			strings.Contains(r.log, "dig ") || strings.Contains(r.log, "helm ") {
			t.Fatalf("exit %d, want a failure before any probe\n%s\n%s", r.code, r.out, r.log)
		}
	})
	t.Run("an open allow-list", func(t *testing.T) {
		wentOnAt(t, runClusterUp(t, apiProbe{dns: "1 " + a, tcp: a + " 1", api: a + " 1", later: "203.0.113.9", cidr: "0.0.0.0/0"}), "3", "4")
	})
	t.Run("this machine's address cannot be learned again", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a, tcp: a + " 1", api: a + " 1", later: "not-an-address"})
		wentOnAt(t, r, "3", "4")
		if !strings.Contains(r.out, "could not learn this machine's public address again; the cluster API allows: 203.0.113.7/32") {
			t.Errorf("not said:\n%s", r.out)
		}
	})
}

// The probe's settings are checked before anything is made.
func TestClusterUpRefusesProbeSettings(t *testing.T) {
	for _, tc := range []struct {
		wait, round, want string
	}{
		{"600", "0", "CLUSTER_API_ROUND must be at least 1 second"},
		{"1", "1", "CLUSTER_API_WAIT (1s) must leave room for 3 rounds of CLUSTER_API_ROUND (1s): at least 2s"},
		{"60", "015", "CLUSTER_API_WAIT and CLUSTER_API_ROUND want whole seconds"},
		{"ten", "1", "CLUSTER_API_WAIT and CLUSTER_API_ROUND want whole seconds"},
	} {
		r := runClusterUp(t, apiProbe{dns: "1 198.51.100.1", wait: tc.wait, round: tc.round})
		if r.code == 0 || !strings.Contains(r.out, tc.want) || strings.Contains(r.log, "terraform") {
			t.Errorf("wait %s, round %s: exit %d, want %q before any Terraform call\n%s\n%s", tc.wait, tc.round, r.code, tc.want, r.out, r.log)
		}
	}
}
