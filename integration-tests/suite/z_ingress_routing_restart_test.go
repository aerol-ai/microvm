//go:build integration

package suite

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-172: with ingress proxy routing, sandboxd is off the data path. Caddy
// splices HTTP/TLS, and the kernel forwards raw TCP via conntrack. So an
// established session must survive a sandboxd restart on BOTH nodes it
// crosses: the ingress that accepted it and the owner behind it.
//
// Nodes are restarted one at a time, each waited to healthy. Restarting
// every Raft voter at once is a different (control-plane) test, and in
// cluster-3-mixed every node is a voter.
func TestIngressRoutingSessionsSurviveSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-172")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	target := newRoutingTarget(t, c)

	// Long-lived raw TCP session.
	tcpConn, err := net.DialTimeout("tcp", target.tcpAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial tcp %s: %v", target.tcpAddr, err)
	}
	defer tcpConn.Close()
	tcpReader := bufio.NewReader(tcpConn)
	if err := echoLine(tcpConn, tcpReader, "before-restart"); err != nil {
		t.Fatalf("tcp echo before restart: %v", err)
	}

	// Long-lived HTTP keep-alive connection.
	httpClient := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Minute}}
	if reused, err := keepAliveGet(httpClient, target.httpURL); err != nil {
		t.Fatalf("http before restart: %v", err)
	} else if reused {
		t.Log("first request reused a connection (fine, just unexpected)")
	}

	// The nodes this session crosses: the ingress the TCP connection landed
	// on (by the address we reached) and the sandbox's owner.
	var restart []harness.IntegrationNode
	seen := map[string]bool{}
	add := func(n harness.IntegrationNode, why string) {
		if n.Name == "" || seen[n.Name] {
			return
		}
		seen[n.Name] = true
		t.Logf("will restart sandboxd on %s (%s)", n.Name, why)
		restart = append(restart, n)
	}
	remoteIP := tcpConn.RemoteAddr().(*net.TCPAddr).IP.String()
	for _, n := range targets.Nodes {
		if n.PublicIP == remoteIP || n.PrivateIP == remoteIP {
			add(n, "ingress for the tcp session")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ownerID, err := c.OwnerNodeID(ctx, target.sb.ID)
	cancel()
	if err != nil {
		t.Fatalf("owner of %s: %v", target.sb.ID, err)
	}
	owner, ok := harness.IntegrationNodeForClusterID(targets, ownerID)
	if !ok {
		t.Fatalf("owner node %q not in the integration targets", ownerID)
	}
	add(owner, "owner")
	if len(restart) == 0 {
		t.Fatal("no node to restart")
	}

	for _, n := range restart {
		harness.RestartSystemdUnit(t, n, "sandboxd")
		waitSandboxdHealthy(t, c, target)
		// Probe the SAME sessions after each restart, not only at the end,
		// so a failure names the node whose restart broke them.
		if err := echoLine(tcpConn, tcpReader, "after-"+n.Name); err != nil {
			t.Fatalf("established tcp session broke across a sandboxd restart on %s: %v", n.Name, err)
		}
		reused, err := keepAliveGet(httpClient, target.httpURL)
		if err != nil {
			t.Fatalf("http after restarting %s: %v", n.Name, err)
		}
		if !reused {
			t.Errorf("the HTTP keep-alive connection was not reused after restarting sandboxd on %s (it was reset)", n.Name)
		}
	}

	// New connections work after the restarts too (the boot re-engage and
	// the kernel rule prune kept the live exposure).
	if err := tcpEchoOnce(target.tcpAddr); err != nil {
		t.Fatalf("fresh tcp connection after the restarts: %v", err)
	}
	if code, err := reachableHTTP(target.httpURL, time.Minute); err != nil || code != http.StatusOK {
		t.Fatalf("fresh http after the restarts: code %d, %v", code, err)
	}
}

// keepAliveGet does one GET and reports whether it rode an already-open
// connection.
func keepAliveGet(c *http.Client, url string) (reused bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection is reusable
	if resp.StatusCode != http.StatusOK {
		return reused, &httpStatusError{code: resp.StatusCode}
	}
	return reused, nil
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return "status " + http.StatusText(e.code) }

// waitSandboxdHealthy waits until the API answers for the target sandbox
// again (the restarted node may be the one the API reached).
func waitSandboxdHealthy(t *testing.T, c *harness.Client, target routingTarget) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := c.SDK().Get(ctx, target.sb.ID)
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("API never answered for %s after the restart: %v", target.sb.ID, err)
		}
		time.Sleep(3 * time.Second)
	}
}
