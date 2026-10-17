package auditlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testdata/pre_caller_chain.jsonl was written by the Event struct as it was
// before the caller field existed (base commit fe956aee, a throwaway
// generator over pkg/auditlog.LinkEvent): a retention checkpoint, secret-open
// success and failure, an egress record with byte counts, a gap marker, a
// retention stub and a managed-owner record. Its hashes are therefore the
// old code's hashes. Never regenerate it with the current struct: the point
// is that bytes written by an older binary keep verifying.
const preCallerChain = "testdata/pre_caller_chain.jsonl"

func readGoldenLines(t *testing.T) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(preCallerChain)
	if err != nil {
		t.Fatalf("read golden chain: %v", err)
	}
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
			lines = append(lines, append([]byte(nil), line...))
		}
	}
	if len(lines) != 7 {
		t.Fatalf("golden chain has %d records, want 7", len(lines))
	}
	return lines
}

// TestPreCallerChainStillVerifies is the old-chain golden test (T4): a chain
// written before Caller existed passes the same verifier the daemon boots
// with and the auditor's CLI runs, and every record decodes into the new
// struct and re-marshals to exactly the bytes on disk, so its hash is
// unchanged.
func TestPreCallerChainStillVerifies(t *testing.T) {
	raw, err := os.ReadFile(preCallerChain)
	if err != nil {
		t.Fatalf("read golden chain: %v", err)
	}
	scan, err := ScanChain(bytes.NewReader(raw), ScanOptions{})
	if err != nil {
		t.Fatalf("pre-caller chain no longer verifies: %v", err)
	}
	if scan.Records != 7 || scan.Redacted != 1 || scan.TornBytes != 0 || scan.MissingNewline {
		t.Fatalf("scan = %+v, want 7 records, 1 stub, no tear", scan)
	}
	if scan.Head != "bb5ea5ceede1042a514463366f402a623cdcacc7415aca958240eeefb8ea5c1f" {
		t.Fatalf("head = %q, want the golden head", scan.Head)
	}
	for i, line := range readGoldenLines(t) {
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("record %d: decode: %v", i, err)
		}
		if ev.Caller != nil {
			t.Fatalf("record %d decoded a caller from a pre-caller line", i)
		}
		again, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("record %d: marshal: %v", i, err)
		}
		if !bytes.Equal(again, line) {
			t.Fatalf("record %d no longer re-marshals byte for byte:\n got %s\nwant %s", i, again, line)
		}
		if ev.Kind == KindRetentionRedacted {
			continue
		}
		if got := HashEvent(ev.PrevHash, ev); got != ev.EventHash {
			t.Fatalf("record %d hash = %s, want the stored %s", i, got, ev.EventHash)
		}
	}
}

// TestNewEventsWithoutCallerHashIdentically: a record built today with no
// caller (a single-node writer before its first request, or any writer
// while the cluster gate is closed) hashes exactly as the old binary hashed
// the same fields.
func TestNewEventsWithoutCallerHashIdentically(t *testing.T) {
	lines := readGoldenLines(t)
	var golden Event
	if err := json.Unmarshal(lines[1], &golden); err != nil {
		t.Fatal(err)
	}
	rebuilt := Event{
		Time:          time.Date(2026, 10, 1, 12, 0, 1, 123456789, time.UTC),
		Actor:         "node-a",
		SandboxID:     "sb-golden",
		Ref:           "env:sb-golden",
		Result:        "success",
		Reason:        "ok",
		CorrelationID: "corr-1",
		EventID:       "ae-golden-1",
		NodeID:        "node-a",
		Kind:          "secret_open",
		IncarnationID: "inc-1",
		OwnerRef:      "team:payments",
	}
	LinkEvent(golden.PrevHash, &rebuilt)
	if rebuilt.EventHash != golden.EventHash {
		t.Fatalf("caller-less record hash = %s, want the pre-caller %s", rebuilt.EventHash, golden.EventHash)
	}
}

// TestCallerIsCoveredByTheHash: attribution is tamper-evident. Rewriting
// any caller field, or stripping the caller, breaks the record.
func TestCallerIsCoveredByTheHash(t *testing.T) {
	base := Event{EventID: "ae-1", SandboxID: "sb-1", Result: "success", Kind: "secret_open"}
	without := HashEvent(GenesisPrevHash, base)
	with := base
	with.Caller = &Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}
	LinkEvent(GenesisPrevHash, &with)
	if with.EventHash == without {
		t.Fatal("caller is not covered by the hash")
	}
	tamper := []func(*Caller){
		func(c *Caller) { c.Kind = "operator" },
		func(c *Caller) { c.ID = "tok_other" },
		func(c *Caller) { c.Name = "someone-else" },
		func(c *Caller) { c.Team = "checkout" },
		func(c *Caller) { c.Via = "" },
	}
	for i, mutate := range tamper {
		forged := with
		c := *with.Caller
		mutate(&c)
		forged.Caller = &c
		v := NewChainVerifier()
		if err := v.Add(forged); err == nil {
			t.Fatalf("tamper %d: a rewritten caller still verified", i)
		}
	}
	stripped := with
	stripped.Caller = nil
	v := NewChainVerifier()
	if err := v.Add(stripped); err == nil {
		t.Fatal("stripping the caller still verified")
	}
	v = NewChainVerifier()
	if err := v.Add(with); err != nil {
		t.Fatalf("intact record with a caller: %v", err)
	}
}

// TestEventFieldOrderIsFrozen pins Event's JSON field order. The hash is
// json.Marshal of the struct, so a reordered or inserted field silently
// changes the hash of every record on disk; new fields are appended, after
// caller.
func TestEventFieldOrderIsFrozen(t *testing.T) {
	want := []string{
		"time", "actor", "sandbox_id", "ref", "result", "reason", "correlation_id", "event_id",
		"node_id", "kind", "destination", "network", "bytes_in", "bytes_out", "incarnation_id",
		"owner_ref", "dropped", "prev_hash", "event_hash", "witnessed_through", "caller",
		"request",
	}
	if got := jsonFieldNames(reflect.TypeOf(Event{})); !reflect.DeepEqual(got, want) {
		t.Fatalf("Event field order = %v\nwant %v (append new fields at the end)", got, want)
	}
	if got := jsonFieldNames(reflect.TypeOf(Caller{})); !reflect.DeepEqual(got, []string{"kind", "id", "name", "team", "via"}) {
		t.Fatalf("Caller field order = %v (append new fields at the end)", got)
	}
	if got := jsonFieldNames(reflect.TypeOf(Request{})); !reflect.DeepEqual(got, []string{
		"method", "route", "status", "digest", "count", "surface", "argv", "target", "routes", "source", "grant",
	}) {
		t.Fatalf("Request field order = %v (append new fields at the end)", got)
	}
	for _, name := range []string{"Caller", "Request"} {
		f, _ := reflect.TypeOf(Event{}).FieldByName(name)
		if !strings.Contains(f.Tag.Get("json"), ",omitempty") {
			t.Fatalf("Event.%s must be omitempty, or every record written before it changes hash", name)
		}
	}
}

func jsonFieldNames(typ reflect.Type) []string {
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
	}
	return names
}

// TestCallerOmittedFieldsStayOff: the optional caller fields are omitted
// when empty, so an operator record stays {"kind","id"}.
func TestCallerOmittedFieldsStayOff(t *testing.T) {
	raw, err := json.Marshal(Event{Result: "success", Caller: &Caller{Kind: "operator", ID: "operator"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"time":"0001-01-01T00:00:00Z","result":"success","caller":{"kind":"operator","id":"operator"}}`
	if string(raw) != want {
		t.Fatalf("marshal = %s\nwant %s", raw, want)
	}
}

// TestRetentionStubDropsTheCaller: a stub keeps only its links, so the
// caller (who opened what) leaves with the payload, and a stub that still
// carries one is refused.
func TestRetentionStubDropsTheCaller(t *testing.T) {
	ev := Event{EventID: "ae-1", Result: "success", Kind: "secret_open", Caller: &Caller{Kind: "oidc", ID: "oidc:okta:00u1", Name: "ana@acme.com"}}
	LinkEvent(GenesisPrevHash, &ev)
	stub := RedactForRetention(ev)
	if stub.Caller != nil {
		t.Fatal("retention stub kept the caller")
	}
	v := NewChainVerifier()
	if err := v.Add(stub); err != nil {
		t.Fatalf("clean stub refused: %v", err)
	}
	dirty := stub
	dirty.Caller = ev.Caller
	v = NewChainVerifier()
	if err := v.Add(dirty); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("stub carrying a caller = %v, want a payload refusal", err)
	}
}

func TestCorrelationContext(t *testing.T) {
	ctx := context.Background()
	if got := CorrelationIDFromContext(ctx); got != "" {
		t.Fatalf("empty context = %q", got)
	}
	if got := ContextWithCorrelationID(ctx, "  "); got != ctx {
		t.Fatal("a blank id must not wrap the context")
	}
	if got := ContextWithCorrelationID(nil, "x"); got != nil {
		t.Fatal("nil context must stay nil")
	}
	if got := CorrelationIDFromContext(nil); got != "" {
		t.Fatalf("nil context = %q", got)
	}
	ctx = ContextWithCorrelationID(ctx, " corr-1 ")
	if got := CorrelationIDFromContext(ctx); got != "corr-1" {
		t.Fatalf("round trip = %q, want corr-1", got)
	}
	a, b := NewCorrelationID(), NewCorrelationID()
	if a == "" || a == b || !strings.Contains(a, "-") {
		t.Fatalf("NewCorrelationID = %q, %q: want two distinct clock-random ids", a, b)
	}
}
