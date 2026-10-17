package auditlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
)

// testdata/pre_request_chain.jsonl was written by the Event struct as it was
// before the request field existed (base identity/04-audit-caller at
// 258ebba6, a throwaway generator over LinkEvent): secret-open records with
// an operator caller, a team token caller with a via, and a system caller,
// an egress record, and a gap marker. Its hashes are the T4 binary's.
// Never regenerate it with the current struct.
const preRequestChain = "testdata/pre_request_chain.jsonl"

// TestPreRequestChainStillVerifies is the T5 old-chain golden test: a
// chain written with callers but before Request existed passes the verifier
// the daemon boots with and the CLI runs, and every line decodes into the
// new struct and re-marshals to exactly its bytes on disk.
func TestPreRequestChainStillVerifies(t *testing.T) {
	raw, err := os.ReadFile(preRequestChain)
	if err != nil {
		t.Fatalf("read golden chain: %v", err)
	}
	scan, err := ScanChain(bytes.NewReader(raw), ScanOptions{})
	if err != nil {
		t.Fatalf("pre-request chain no longer verifies: %v", err)
	}
	if scan.Records != 5 || scan.TornBytes != 0 || scan.MissingNewline {
		t.Fatalf("scan = %+v, want 5 records, no tear", scan)
	}
	if scan.Head != "e5fd8beba90e630d5bdc227b4f0c3323f9be8b7fbef61d0bec2bf7ff048c4084" {
		t.Fatalf("head = %q, want the golden head", scan.Head)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	i := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("record %d: decode: %v", i, err)
		}
		if ev.Request != nil {
			t.Fatalf("record %d decoded a request from a pre-request line", i)
		}
		again, _ := json.Marshal(ev)
		if !bytes.Equal(again, line) {
			t.Fatalf("record %d no longer re-marshals byte for byte:\n got %s\nwant %s", i, again, line)
		}
		if got := HashEvent(ev.PrevHash, ev); got != ev.EventHash {
			t.Fatalf("record %d hash = %s, want the stored %s", i, got, ev.EventHash)
		}
		i++
	}
	if i != 5 {
		t.Fatalf("read %d records, want 5", i)
	}
}

// TestRequestIsCoveredByTheHash: the call a record describes is
// tamper-evident, field by field, and so is stripping it.
func TestRequestIsCoveredByTheHash(t *testing.T) {
	base := Event{EventID: "ae-1", SandboxID: "sb-1", Result: APIResultOK, Kind: KindAPI,
		Caller:  &Caller{Kind: "token", ID: "tok_1"},
		Request: &Request{Method: "POST", Route: "/v1/sandboxes/{id}/exec", Status: 200, Digest: "d1", Surface: SurfaceMCP, Argv: []string{"ls"}, Target: "t"}}
	with := base
	LinkEvent(GenesisPrevHash, &with)
	tampers := []func(*Request){
		func(r *Request) { r.Method = "GET" },
		func(r *Request) { r.Route = "/v1/sandboxes/{id}" },
		func(r *Request) { r.Status = 500 },
		func(r *Request) { r.Digest = "d2" },
		func(r *Request) { r.Count = 2 },
		func(r *Request) { r.Surface = "" },
		func(r *Request) { r.Argv = []string{"rm", "-rf"} },
		func(r *Request) { r.Target = "u" },
		func(r *Request) { r.Routes = []string{"x"} },
		func(r *Request) { r.Source = "10.0.0.1" },
	}
	for i, tamper := range tampers {
		forged := with
		req := *with.Request
		tamper(&req)
		forged.Request = &req
		v := NewChainVerifier()
		if err := v.Add(forged); err == nil {
			t.Fatalf("tamper %d: a rewritten request still verified", i)
		}
	}
	stripped := with
	stripped.Request = nil
	v := NewChainVerifier()
	if err := v.Add(stripped); err == nil {
		t.Fatal("stripping the request still verified")
	}
	v = NewChainVerifier()
	if err := v.Add(with); err != nil {
		t.Fatalf("intact record: %v", err)
	}
}

// TestRequestOmittedFieldsStayOff: every request field is omitempty, so a
// record carries only what applies to it.
func TestRequestOmittedFieldsStayOff(t *testing.T) {
	raw, _ := json.Marshal(Event{Result: APIResultOK, Kind: KindAPI, Request: &Request{Method: "DELETE", Route: "/v1/sandboxes/{id}", Status: 204}})
	want := `{"time":"0001-01-01T00:00:00Z","result":"ok","kind":"api","request":{"method":"DELETE","route":"/v1/sandboxes/{id}","status":204}}`
	if string(raw) != want {
		t.Fatalf("marshal = %s\nwant %s", raw, want)
	}
}

// TestRetentionStubDropsTheRequest: a stub keeps only its links; one that
// still carries the call is refused.
func TestRetentionStubDropsTheRequest(t *testing.T) {
	ev := Event{EventID: "ae-1", Result: APIResultOK, Kind: KindAPI, Request: &Request{Method: "POST", Argv: []string{"cat", "/secret"}}}
	LinkEvent(GenesisPrevHash, &ev)
	stub := RedactForRetention(ev)
	if stub.Request != nil {
		t.Fatal("retention stub kept the request")
	}
	dirty := stub
	dirty.Request = ev.Request
	v := NewChainVerifier()
	if err := v.Add(dirty); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("stub carrying a request = %v, want a payload refusal", err)
	}
}

func TestAPIResultForStatus(t *testing.T) {
	cases := map[int]string{
		101: APIResultOK, 200: APIResultOK, 204: APIResultOK, 302: APIResultOK,
		401: APIResultDenied, 403: APIResultDenied,
		400: APIResultError, 404: APIResultError, 409: APIResultError, 502: APIResultError,
	}
	for status, want := range cases {
		if got := APIResultForStatus(status); got != want {
			t.Errorf("APIResultForStatus(%d) = %q, want %q", status, got, want)
		}
	}
}

// TestCallState: the per-request record state the edge attaches and the
// layers below only mark. Every helper is a no-op without one.
func TestCallState(t *testing.T) {
	bare := context.Background()
	MarkForwarded(bare)
	MarkForwardFailed(bare)
	NoteSandbox(bare, "sb")
	NoteTarget(bare, "t")
	if CallStateFromContext(bare) != nil || CallStateFromContext(nil) != nil {
		t.Fatal("a context without state must report none")
	}
	var none *CallState
	if none.Forwarded() || none.ForwardFailed() || none.SandboxID() != "" || none.Target() != "" {
		t.Fatal("a nil state reports nothing")
	}

	ctx, st := ContextWithCallState(nil)
	if CallStateFromContext(ctx) != st {
		t.Fatal("state round trip")
	}
	NoteSandbox(ctx, "  ")
	NoteTarget(ctx, "")
	if st.SandboxID() != "" || st.Target() != "" {
		t.Fatal("blank notes must not overwrite")
	}
	NoteSandbox(ctx, " sb-1 ")
	NoteTarget(ctx, " tok_9 ")
	if st.SandboxID() != "sb-1" || st.Target() != "tok_9" {
		t.Fatalf("notes = %q %q", st.SandboxID(), st.Target())
	}
	NoteSandboxIdentity(ctx, "sb-1", " inc-1 ", "team:payments")
	if id, inc, owner := st.SandboxIdentity(); id != "sb-1" || inc != "inc-1" || owner != "team:payments" {
		t.Fatalf("identity = %q %q %q", id, inc, owner)
	}
	if _, _, owner := none.SandboxIdentity(); owner != "" {
		t.Fatal("a nil state has no identity")
	}
	// A nested request (a remote MCP tool's inner call) gets its own state:
	// marking it leaves the outer one alone.
	inner, innerSt := ContextWithCallState(ctx)
	MarkForwarded(inner)
	if !innerSt.Forwarded() || st.Forwarded() {
		t.Fatal("marking the inner state touched the outer one")
	}
	MarkForwarded(ctx)
	MarkForwardFailed(ctx)
	if !st.Forwarded() || !st.ForwardFailed() {
		t.Fatal("forward marks lost")
	}
	// Notes may come from any goroutine (a handler's helpers).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); NoteSandbox(ctx, "sb-2"); _ = st.SandboxID() }()
	}
	wg.Wait()
	if st.SandboxID() != "sb-2" {
		t.Fatalf("concurrent notes = %q", st.SandboxID())
	}
}

func TestSurfaceContext(t *testing.T) {
	if SurfaceFromContext(context.Background()) != "" || SurfaceFromContext(nil) != "" {
		t.Fatal("no surface by default")
	}
	if got := SurfaceFromContext(ContextWithSurface(nil, SurfaceMCP)); got != SurfaceMCP {
		t.Fatalf("surface = %q", got)
	}
}
