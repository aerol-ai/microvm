package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cluster.sh up waits until every address the new cluster's API name
// resolves to answers from this machine, before its first kubectl or Helm
// call (bank-1's first run: one of two addresses never answered, and the
// Karpenter install timed out 17 minutes in). These run the real cluster.sh
// up against stubs: dig answers per round from a table, nc and kubectl
// answer per address from the round they are listed from.

// apiProbe is one cluster.sh up run's world.
type apiProbe struct {
	// dns: "<from round> <address>..." lines; each round uses the last
	// line whose round has come.
	dns string
	// tcp and api: "<address> <from round>" lines: nc connects, and
	// /version answers, through that address from that round on. An
	// address not listed never does.
	tcp, api string
	// ip is this machine's address when up starts (the API allows it);
	// later is the one it learns again before the probe ("" = the same).
	ip, later string
	wait      string
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
	if p.wait == "" {
		p.wait = "3"
	}
	for f, body := range map[string]string{"dns": p.dns, "tcp": p.tcp, "api": p.api} {
		if err := os.WriteFile(filepath.Join(world, f), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// at <table> <address>: does the address answer in this round?
	at := `at() { from=$(awk -v a="$2" '$1==a {print $2}' "$STUB_DIR/$1"); r=$(cat "$STUB_DIR/round" 2>/dev/null || echo 0); [ -n "$from" ] && [ "$r" -ge "$from" ]; }`
	stubs := map[string]string{
		"aws": `echo "aws $*" >> "$STUB_LOG"
case "$*" in
  *"sts get-caller-identity"*) echo 111122223333 ;;
  *"eks update-kubeconfig"*) : ;;
  *"eks describe-cluster"*) printf '{"cluster":{"endpoint":"https://ABCD1234.yl4.us-east-1.eks.amazonaws.com","resourcesVpcConfig":{"publicAccessCidrs":["%s/32"]}}}\n' "$STUB_IP" ;;
  *) exit 1 ;;
esac`,
		"terraform": `echo "terraform $*" >> "$STUB_LOG"
case "$*" in *output*region*) echo us-east-1 ;; esac`,
		"curl": `echo "curl $*" >> "$STUB_LOG"
n=$(( $(cat "$STUB_DIR/curls" 2>/dev/null || echo 0) + 1 )); echo $n > "$STUB_DIR/curls"
[ "$n" = 1 ] && echo "$STUB_IP" || echo "$STUB_IP_LATER"`,
		// A round is one resolve. A CNAME line first, as dig prints one.
		"dig": `echo "dig $*" >> "$STUB_LOG"
r=$(( $(cat "$STUB_DIR/round" 2>/dev/null || echo 0) + 1 )); echo $r > "$STUB_DIR/round"
echo "api.elb.example."
awk -v r=$r 'NF && $1<=r {line=$0} END {n=split(line,a," "); for(i=2;i<=n;i++) print a[i]}' "$STUB_DIR/dns"`,
		// macOS's nc: -h lists -G, which the probe must then use.
		"nc": at + `
[ "$1" = -h ] && { printf 'usage: nc\n\t-G conntimo\tConnection timeout in seconds\n' >&2; exit 1; }
echo "nc $*" >> "$STUB_LOG"
for a; do prev=$last; last=$a; done
at tcp "$prev"`,
		"kubectl": at + `
echo "kubectl $*" >> "$STUB_LOG"
addr=$(echo "$*" | sed -n 's#.*--server https://\([0-9.]*\).*#\1#p')
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
		"STUB_LOG="+log, "STUB_DIR="+world, "STUB_IP="+p.ip, "STUB_IP_LATER="+p.later,
		"CLUSTER_API_WAIT="+p.wait, "CLUSTER_API_ROUND=1", "HELM=helm", "TF_VAR_region=")
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

func TestClusterUpWaitsForEveryAPIAddress(t *testing.T) {
	const a, b, c = "198.51.100.1", "198.51.100.2", "198.51.100.3"
	t.Run("every address answers", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1\n" + b + " 1", api: a + " 1\n" + b + " 1"})
		if r.code != 0 || !strings.Contains(r.out, "every cluster API address answers from this machine: "+a+" "+b) || !helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
		// The connect is bounded the macOS way, and /version goes through
		// each address with the run's kubeconfig and the API's own name.
		for _, want := range []string{"nc -z -G 5 -w 5 " + b + " 443",
			"--server https://" + b + " --tls-server-name ABCD1234.yl4.us-east-1.eks.amazonaws.com --request-timeout=10s get --raw /version",
			".state/bank-1/kubeconfig"} {
			if !strings.Contains(r.log, want) {
				t.Errorf("no %q in the calls:\n%s", want, r.log)
			}
		}
		if !strings.Contains(r.out, "the cluster API allows this machine's address 203.0.113.7/32") {
			t.Errorf("the allowed range was not checked:\n%s", r.out)
		}
	})
	t.Run("one address never answers", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1", api: a + " 1"})
		want := "the cluster API address " + b + " does not answer from this machine (waited 3s"
		if r.code == 0 || !strings.Contains(r.out, want) || helmInstalled(t, r) || strings.Contains(r.log, "helm ") {
			t.Fatalf("exit %d, want a failure naming %s and no Helm call\n%s\n%s", r.code, b, r.out, r.log)
		}
		if !strings.Contains(r.out, "round 3: answers: "+a+"; does not answer: "+b+" (no TCP connect on 443)") {
			t.Errorf("it did not keep trying, or did not log each round:\n%s", r.out)
		}
	})
	t.Run("an address answers from round 3", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1\n" + b + " 3", api: a + " 1\n" + b + " 1", wait: "10"})
		if r.code != 0 || !helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
		for _, want := range []string{"round 2: answers: " + a + "; does not answer: " + b, "round 3: answers: " + a + " " + b + "; does not answer: none"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("no %q:\n%s", want, r.out)
			}
		}
		if strings.Contains(r.out, "round 4") {
			t.Errorf("it went on probing after every address answered:\n%s", r.out)
		}
	})
	t.Run("a connect but no /version", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b, tcp: a + " 1\n" + b + " 1", api: a + " 1"})
		if r.code == 0 || !strings.Contains(r.out, "the cluster API address "+b+" does not answer from this machine") ||
			!strings.Contains(r.out, b+" (no answer to /version)") || helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
	})
	t.Run("the name is resolved again each round", func(t *testing.T) {
		// The dead address leaves the name on round 3, a live one joins.
		r := runClusterUp(t, apiProbe{dns: "1 " + a + " " + b + "\n3 " + a + " " + c, tcp: a + " 1\n" + c + " 1", api: a + " 1\n" + c + " 1", wait: "10"})
		if r.code != 0 || !strings.Contains(r.out, "every cluster API address answers from this machine: "+a+" "+c) || !helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
	})
	t.Run("the name resolves to nothing", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: ""})
		if r.code == 0 || !strings.Contains(r.out, "the cluster API name ABCD1234.yl4.us-east-1.eks.amazonaws.com resolves to no address from this machine") || helmInstalled(t, r) {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
		}
	})
	t.Run("this machine's address changed", func(t *testing.T) {
		r := runClusterUp(t, apiProbe{dns: "1 " + a, tcp: a + " 1", api: a + " 1", later: "203.0.113.9"})
		if !strings.Contains(r.out, "this machine's address is now 203.0.113.9/32, which the cluster API does not allow (it allows: 203.0.113.7/32); cluster.sh allow-ip bank-1 adds it") {
			t.Fatalf("the changed address was not reported:\n%s", r.out)
		}
	})
}
