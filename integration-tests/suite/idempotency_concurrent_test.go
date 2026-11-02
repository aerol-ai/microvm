//go:build integration

package suite

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-367 — concurrent retries of one Idempotency-Key create make one sandbox
// and leave its capacity reservation in place.
//
// An SDK retries a create after a proxy 502/504, a reset or a client timeout,
// while the first attempt may still be running (a slow image pull). Each
// retry used to run a second create of the same sandbox id on the owner,
// fail on the container name with 409, and on its way out release the first
// create's capacity reservation and unmount its mounts: the sandbox ran on,
// while GET /v1/capacity showed cpu=0 mem=0 active=0 for it. Now a retry
// waits for the create it repeats and replays it.
//
// The case fires N creates (AEROL_UC367_CONCURRENCY, default 8) with one key
// and one body at the same instant, spread across every ingress node the
// scenario has (one node in local and single-node scenarios), and asserts:
// every answer is 201 naming the same sandbox; exactly one sandbox carries
// the request's tag; and the owner node's capacity view counts exactly one
// sandbox's reservation for it, measured as what deleting the sandbox gives
// back (warm-pool parks excluded), so other residents of the node do not
// matter. AEROL_UC367_IMAGE picks a slower image to widen the race.
func TestV1ConcurrentKeyedCreatesMakeOneSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-367")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	n := benchEnvInt("AEROL_UC367_CONCURRENCY", 8)
	key := "uc367-" + harness.UniqueName(sc, t)
	// An odd size, so the reservation it holds is unmistakable.
	const cpu, memoryMB = 0.75, 640
	body, err := json.Marshal(map[string]any{
		"image":     envOr("AEROL_UC367_IMAGE", "alpine:3.20"),
		"cpu":       cpu,
		"memory_mb": memoryMB,
		"tags":      map[string]string{"uc367": key},
	})
	if err != nil {
		t.Fatal(err)
	}

	clients, vias := uc367Clients(t)
	type answer struct {
		via    string
		status int
		body   string
		id     string
		err    error
	}
	answers := make([]answer, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hc, via := clients[i%len(clients)], vias[i%len(vias)]
			<-start
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(sc.BaseURL, "/")+"/v1/sandboxes", bytes.NewReader(body))
			if err != nil {
				answers[i] = answer{via: via, err: err}
				return
			}
			req.Header.Set("Authorization", "Bearer "+sc.PAT)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
			resp, err := hc.Do(req)
			if err != nil {
				answers[i] = answer{via: via, err: err}
				return
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			var created idResponse
			_ = json.Unmarshal(raw, &created)
			answers[i] = answer{via: via, status: resp.StatusCode, body: string(raw), id: created.ID}
		}()
	}
	close(start)
	wg.Wait()

	id := ""
	for i, a := range answers {
		if a.err != nil {
			t.Fatalf("create %d via %s: %v", i, a.via, a.err)
		}
		if a.status != http.StatusCreated || a.id == "" {
			t.Fatalf("create %d via %s = %d %s; want 201 naming the sandbox (a retry must wait and replay, never 409 or 5xx)", i, a.via, a.status, a.body)
		}
		if id == "" {
			id = a.id
			destroySandbox(t, id)
		}
		if a.id != id {
			t.Fatalf("create %d via %s named %s, another create named %s: one key made two sandboxes", i, a.via, a.id, id)
		}
	}
	t.Logf("%d concurrent creates through %d ingress endpoint(s) all named %s", n, len(clients), id)

	// Exactly one sandbox carries this request's tag, cluster-wide.
	st, raw := fcDo(t, ctx, http.MethodGet, "", "/v1/sandboxes?tag.uc367="+url.QueryEscape(key), nil, nil)
	var listed []idResponse
	if st != http.StatusOK || json.Unmarshal(raw, &listed) != nil {
		t.Fatalf("list by tag = %d %s", st, raw)
	}
	if len(listed) != 1 || listed[0].ID != id {
		t.Fatalf("sandboxes tagged with the key = %+v; want exactly %s", listed, id)
	}

	// The owner's capacity view holds this sandbox's reservation: deleting
	// the sandbox gives back exactly one sandbox at its size. A retry that
	// released it would leave nothing to give back.
	capacityURL := uc367OwnerAPI(t, c, id)
	before := uc367Capacity(t, ctx, capacityURL)
	if st, b := fcDo(t, ctx, http.MethodDelete, "", "/v1/sandboxes/"+id, nil, nil); st != http.StatusOK && st != http.StatusNoContent && st != http.StatusAccepted {
		t.Fatalf("delete %s = %d %s", id, st, b)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		st, _ := fcDo(t, ctx, http.MethodGet, "", "/v1/sandboxes/"+id, nil, nil)
		if st == http.StatusNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still answers %d two minutes after its delete", id, st)
		}
		time.Sleep(2 * time.Second)
	}
	after := uc367Capacity(t, ctx, capacityURL)
	freed := before.minus(after)
	t.Logf("owner capacity before delete %+v, after %+v", before, after)
	if freed.active != 1 || freed.cpu != cpu || freed.memoryMB != memoryMB {
		t.Fatalf("deleting the sandbox gave back active=%d cpu=%v mem=%d; want exactly one sandbox at cpu=%v mem=%d (its reservation was lost or doubled)",
			freed.active, freed.cpu, freed.memoryMB, cpu, memoryMB)
	}
}

// uc367Clients returns one HTTP client per ingress node, each dialing only
// that node with the real hostname, and the node names for the log. Without
// integration targets (local mode) it is the scenario's one endpoint.
func uc367Clients(t *testing.T) ([]*http.Client, []string) {
	t.Helper()
	ingress := ingressNodes(harness.LoadIntegrationTargets())
	if len(ingress) == 0 {
		return []*http.Client{harness.HTTPClient(0)}, []string{sc.BaseURL}
	}
	clients := make([]*http.Client, 0, len(ingress))
	names := make([]string, 0, len(ingress))
	for _, node := range ingress {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = pinnedDial(node.PublicIP)
		t.Cleanup(tr.CloseIdleConnections)
		clients = append(clients, &http.Client{Transport: tr})
		names = append(names, node.Name)
	}
	return clients, names
}

// uc367OwnerAPI returns a base URL that reaches sandboxd on the node owning
// sandboxID: the scenario's endpoint when there is one node (or no targets),
// else the owner's loopback daemon over SSH. GET /v1/capacity is node-local,
// so only the owner's answer counts the sandbox.
func uc367OwnerAPI(t *testing.T, c *harness.Client, sandboxID string) string {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) <= 1 || !sc.Has(harness.CapCluster) {
		return sc.BaseURL
	}
	owner := resolvePlacementOwner(t, c, sandboxID)
	if owner == "" {
		t.Fatalf("no placement owner recorded for %s", sandboxID)
	}
	for _, node := range targets.Nodes {
		if _, ok := harness.SSHTarget(node); !ok {
			continue
		}
		if heteroNodeID(t, c, targets, node.Name) == owner {
			return "http://" + harness.SSHForward(t, node, "127.0.0.1:21212")
		}
	}
	t.Fatalf("the owner %s of %s is not SSH-reachable; its capacity view cannot be read", owner, sandboxID)
	return ""
}

type uc367Reservation struct {
	active   int
	cpu      float64
	memoryMB int
}

func (a uc367Reservation) minus(b uc367Reservation) uc367Reservation {
	return uc367Reservation{active: a.active - b.active, cpu: a.cpu - b.cpu, memoryMB: a.memoryMB - b.memoryMB}
}

// uc367Capacity reads a node's sandbox reservations from GET /v1/capacity,
// warm-pool parks excluded.
func uc367Capacity(t *testing.T, ctx context.Context, baseURL string) uc367Reservation {
	t.Helper()
	st, raw := fcDo(t, ctx, http.MethodGet, baseURL, "/v1/capacity", nil, nil)
	var snap struct {
		SandboxesActive  int     `json:"sandboxes_active"`
		ReservedCPU      float64 `json:"reserved_cpu"`
		ReservedMemoryMB int     `json:"reserved_memory_mb"`
		ParkedCPU        float64 `json:"parked_cpu"`
		ParkedMemoryMB   int     `json:"parked_memory_mb"`
		ParkedSlots      int     `json:"parked_slots"`
	}
	if st != http.StatusOK || json.Unmarshal(raw, &snap) != nil {
		t.Fatalf("GET %s/v1/capacity = %d %s", baseURL, st, raw)
	}
	// Round away float noise in the CPU sum (fractional reservations).
	cpu := float64(int((snap.ReservedCPU-snap.ParkedCPU)*1000+0.5)) / 1000
	return uc367Reservation{
		active:   snap.SandboxesActive - snap.ParkedSlots,
		cpu:      cpu,
		memoryMB: snap.ReservedMemoryMB - snap.ParkedMemoryMB,
	}
}
