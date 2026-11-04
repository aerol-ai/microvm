package auditlog

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSearchFilterMatch(t *testing.T) {
	at := t0.Add(time.Hour)
	ana := &Caller{Kind: "oidc", ID: "oidc:okta:00u1", Name: "Ana@Acme.com", Team: "payments"}
	api := Event{Time: at, Kind: KindAPI, Result: APIResultOK, SandboxID: "sb-1", Caller: ana}
	cases := []struct {
		name string
		f    SearchFilter
		ev   Event
		want bool
	}{
		{"empty filter matches a record", SearchFilter{}, api, true},
		{"caller by id", SearchFilter{Caller: "oidc:okta:00u1"}, api, true},
		{"caller by name, any case", SearchFilter{Caller: "ana@acme.com"}, api, true},
		{"other caller", SearchFilter{Caller: "tok_x"}, api, false},
		{"no caller on the record", SearchFilter{Caller: "tok_x"}, Event{Time: at, Kind: KindAPI}, false},
		{"a nameless caller never matches an empty-name probe", SearchFilter{Caller: "x"}, Event{Kind: KindAPI, Caller: &Caller{ID: "y"}}, false},
		{"kind", SearchFilter{Kind: KindAPI}, api, true},
		{"other kind", SearchFilter{Kind: KindAuthDenied}, api, false},
		{"sandbox", SearchFilter{SandboxID: "sb-1"}, api, true},
		{"other sandbox", SearchFilter{SandboxID: "sb-2"}, api, false},
		{"result", SearchFilter{Result: APIResultOK}, api, true},
		{"other result", SearchFilter{Result: APIResultDenied}, api, false},
		{"since is inclusive", SearchFilter{Since: at}, api, true},
		{"before since", SearchFilter{Since: at.Add(time.Second)}, api, false},
		{"until is exclusive", SearchFilter{Until: at}, api, false},
		{"before until", SearchFilter{Until: at.Add(time.Second)}, api, true},
		{"checkpoints are structure, not evidence", SearchFilter{}, Event{Kind: KindRetentionCheckpoint}, false},
		{"stubs are structure, not evidence", SearchFilter{}, Event{Kind: KindRetentionRedacted}, false},
		{"unless asked for by kind", SearchFilter{Kind: KindRetentionRedacted}, Event{Kind: KindRetentionRedacted}, true},
	}
	for _, c := range cases {
		if got := c.f.Match(c.ev); got != c.want {
			t.Errorf("%s: Match = %v, want %v", c.name, got, c.want)
		}
	}
}

// searchHistory is one node's honest history with api records from two
// callers interleaved with secret opens, exported in batches of six.
func searchHistory() (*memExport, []Event) {
	callers := []*Caller{
		{Kind: "token", ID: "tok_ci", Name: "ci-deploy", Team: "payments"},
		{Kind: "oidc", ID: "oidc:okta:00u1", Name: "ana@acme.com", Team: "payments"},
	}
	prev := GenesisPrevHash
	var evs []Event
	for i := 0; i < 30; i++ {
		ev := Event{Time: t0.Add(time.Duration(i) * 10 * time.Minute), EventID: "s-" + string(rune('a'+i)), SandboxID: "sb-1", Caller: callers[i%2]}
		switch i % 3 {
		case 0:
			ev.Kind, ev.Result, ev.Ref = "secret_open", "success", "env:sb-1"
		default:
			ev.Kind, ev.Result, ev.Ref = KindAPI, APIResultOK, "POST /v1/sandboxes/{id}/toolbox/{path...}"
			ev.Request = &Request{Method: "POST", Route: "/v1/sandboxes/{id}/toolbox/{path...}", Status: 200, Digest: "d"}
		}
		if i == 7 {
			ev.Result = APIResultDenied
			ev.Request.Status = 403
		}
		LinkEvent(prev, &ev)
		prev = ev.EventHash
		evs = append(evs, ev)
	}
	exp := newMemExport()
	for start := 0; start < len(evs); start += 6 {
		end := min(start+6, len(evs))
		exp.put(evs[end-1].Time.UTC().Format("2006-01-02"), "b"+string(rune('a'+start/6))+".jsonl", evs[start:end])
	}
	return exp, evs
}

func TestSearchNodeFindsVerifiedRecords(t *testing.T) {
	exp, evs := searchHistory()
	in := NodeInput{NodeID: "node-a", Since: t0, Now: evs[len(evs)-1].Time.Add(time.Minute), Export: exp, NoWitness: true}
	var got []Event
	rep, err := SearchNode(context.Background(), in, SearchFilter{Caller: "ana@acme.com", Kind: KindAPI}, func(ev Event) { got = append(got, ev) })
	if err != nil {
		t.Fatalf("SearchNode: %v", err)
	}
	wantResult(t, rep, ResultPass, "")
	if rep.RecordsChecked != int64(len(evs)) || rep.Silent {
		t.Fatalf("report = %+v, want every record checked and no silent warning", rep)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "no witness given") {
		t.Fatalf("warnings = %q, want the no-witness note", rep.Warnings)
	}
	// Ana is the odd records; api records are the ones not divisible by 3.
	var want []string
	for i, ev := range evs {
		if i%2 == 1 && i%3 != 0 {
			want = append(want, ev.EventID)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("matched %d records, want %d", len(got), len(want))
	}
	for i, ev := range got {
		if ev.EventID != want[i] || ev.Caller.ID != "oidc:okta:00u1" {
			t.Fatalf("match %d = %s by %s, want %s by ana (chain order)", i, ev.EventID, ev.Caller.ID, want[i])
		}
	}

	var denied []Event
	if _, err := SearchNode(context.Background(), in, SearchFilter{Result: APIResultDenied}, func(ev Event) { denied = append(denied, ev) }); err != nil {
		t.Fatal(err)
	}
	if len(denied) != 1 || denied[0].EventID != evs[7].EventID {
		t.Fatalf("denied = %+v, want the one 403", denied)
	}
	// A nil callback walks and verifies without collecting (access review
	// passes its own).
	if rep, err := SearchNode(context.Background(), in, SearchFilter{}, nil); err != nil || rep.Result != ResultPass {
		t.Fatalf("nil callback: %+v %v", rep, err)
	}
}

// TestSearchNodeTamperedBatchFails: a rewritten record breaks the chain, so
// the walk stops at it and the verdict is FAIL. The caller of SearchNode
// must not present matches from a failed history as evidence.
func TestSearchNodeTamperedBatchFails(t *testing.T) {
	exp, evs := searchHistory()
	forged := append([]Event(nil), evs[12:18]...)
	forged[2].Caller = &Caller{Kind: "token", ID: "tok_someone_else"}
	exp.put(evs[17].Time.UTC().Format("2006-01-02"), "bc.jsonl", forged)
	in := NodeInput{NodeID: "node-a", Since: t0, Now: evs[len(evs)-1].Time.Add(time.Minute), Export: exp, NoWitness: true}
	var got []Event
	rep, err := SearchNode(context.Background(), in, SearchFilter{Caller: "tok_someone_else"}, func(ev Event) { got = append(got, ev) })
	if err != nil {
		t.Fatalf("SearchNode: %v", err)
	}
	wantResult(t, rep, ResultFail, "does not link")
	if len(got) != 0 {
		t.Fatalf("the forged record was returned as a match: %+v", got)
	}
}

// TestSearchNodeWithWitness: with heads, the search is a full verification
// too.
func TestSearchNodeWithWitness(t *testing.T) {
	h := newHistory(120, 7)
	var n int
	rep, err := SearchNode(context.Background(), h.input(), SearchFilter{SandboxID: "sb"}, func(Event) { n++ })
	if err != nil {
		t.Fatal(err)
	}
	wantResult(t, rep, ResultPass, "")
	if rep.HeadsLinked != rep.HeadsInWindow || n == 0 {
		t.Fatalf("heads %d/%d linked, %d matches", rep.HeadsLinked, rep.HeadsInWindow, n)
	}
}
