package rootpolicy

import (
	"slices"
	"testing"

	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/filters"
)

// agentEventFilters are the filters sandboxd's event monitor subscribes
// with (internal/runtime/containerd events.go StreamEvents).
var agentEventFilters = []string{`topic~="/tasks/"`, `topic=="/containers/delete"`}

func TestScopeEventFilters(t *testing.T) {
	p := testPolicy()
	sel := `namespace=="aerolvm"`
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"no filters", nil, []string{sel}},
		{"an empty filter", []string{""}, []string{sel}},
		{"the agent's", agentEventFilters, []string{sel + `,topic~="/tasks/"`, sel + `,topic=="/containers/delete"`}},
		{"one that names another namespace", []string{`namespace==k8s.io`}, []string{sel + `,namespace==k8s.io`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ScopeEventFilters(p, tc.in)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	for _, bad := range [][]string{{`topic==`}, {`topic~="/tasks/"`, `,`}, {`"unterminated`}} {
		_, err := ScopeEventFilters(p, bad)
		wantRule(t, err, RuleNamespace)
	}
}

// scopedMatches parses fs as containerd's event exchange does and reports
// whether it lets env through.
func scopedMatches(t testing.TB, fs []string, env *events.Envelope) bool {
	t.Helper()
	f, err := filters.ParseAll(fs...)
	if err != nil {
		t.Fatalf("%q does not parse: %v", fs, err)
	}
	return f.Match(env)
}

var otherNamespaces = []string{"k8s.io", "", "aerolvm2", "AEROLVM", "default", "aerolvm ", "moby"}

// TestScopedEventFilters: the agent's event monitor still gets its events,
// and no subscription gets another namespace's.
func TestScopedEventFilters(t *testing.T) {
	p := testPolicy()
	scoped, err := ScopeEventFilters(p, agentEventFilters)
	if err != nil {
		t.Fatal(err)
	}
	for _, topic := range []string{"/tasks/exit", "/tasks/start", "/tasks/oom", "/tasks/delete", "/containers/delete"} {
		if !scopedMatches(t, scoped, &events.Envelope{Namespace: p.Namespace, Topic: topic}) {
			t.Errorf("the agent no longer gets %s", topic)
		}
		for _, ns := range otherNamespaces {
			if scopedMatches(t, scoped, &events.Envelope{Namespace: ns, Topic: topic}) {
				t.Errorf("%s from namespace %q gets through", topic, ns)
			}
		}
	}
	if scopedMatches(t, scoped, &events.Envelope{Namespace: p.Namespace, Topic: "/images/create"}) {
		t.Error("scoping widened the agent's topics")
	}
}

// FuzzScopeEventFilters: whatever filters a broken agent sends, the scoped
// list either does not parse (refused) or lets no other namespace's event
// through, and it never loses an event of the agent's namespace that the
// agent's own filters matched.
func FuzzScopeEventFilters(f *testing.F) {
	f.Add(`topic~="/tasks/"`, `topic=="/containers/delete"`)
	f.Add(``, `namespace==k8s.io`)
	f.Add(`namespace!=aerolvm`, `topic~=".*"`)
	f.Add(`topic`, `namespace~="."`)
	f.Add(`"namespace"=="k8s.io"`, `topic=="/tasks/exit",namespace=="k8s.io"`)
	p := testPolicy()
	f.Fuzz(func(t *testing.T, a, b string) {
		in := []string{a, b}
		scoped, err := ScopeEventFilters(p, in)
		if err != nil {
			if RuleOf(err) != RuleNamespace {
				t.Fatalf("refusal names no rule: %v", err)
			}
			return
		}
		orig, origErr := filters.ParseAll(in...)
		for _, topic := range []string{"/tasks/exit", "/containers/delete", "/images/create", ""} {
			for _, ns := range otherNamespaces {
				if scopedMatches(t, scoped, &events.Envelope{Namespace: ns, Topic: topic}) {
					t.Fatalf("%q scoped to %q lets %q from %q through", in, scoped, topic, ns)
				}
			}
			own := &events.Envelope{Namespace: p.Namespace, Topic: topic}
			if origErr == nil && orig.Match(own) && !scopedMatches(t, scoped, own) {
				t.Fatalf("%q scoped to %q loses the agent's %q", in, scoped, topic)
			}
		}
	})
}
