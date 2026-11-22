package gate

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/filters"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

const subscribe = "/containerd.services.events.v1.Events/Subscribe"

// nodeEvents is what containerd's exchange carries on a node the agent
// shares with Kubernetes: every namespace's events.
var nodeEvents = []*types.Envelope{
	{Namespace: testNS, Topic: "/tasks/exit"},
	{Namespace: "k8s.io", Topic: "/tasks/exit"},
	{Namespace: testNS, Topic: "/containers/delete"},
	{Namespace: "k8s.io", Topic: "/containers/delete"},
	{Namespace: "", Topic: "/tasks/oom"},
	{Namespace: "moby", Topic: "/tasks/start"},
	{Namespace: testNS, Topic: "/images/create"},
}

// subscribeLikeContainerd answers a subscription as containerd does: every
// event on the node that one of the request's filters matches, whatever
// the caller's namespace (plugins/services/events Subscribe).
func subscribeLikeContainerd(_ context.Context, q proto.Message) ([]proto.Message, error) {
	f, err := filters.ParseAll(q.(*eventsapi.SubscribeRequest).GetFilters()...)
	if err != nil {
		return nil, err
	}
	var out []proto.Message
	for _, e := range nodeEvents {
		if f.Match(&events.Envelope{Namespace: e.GetNamespace(), Topic: e.GetTopic()}) {
			out = append(out, e)
		}
	}
	return out, nil
}

// sendsAll is a containerd that ignored the filters altogether.
func sendsAll(context.Context, proto.Message) ([]proto.Message, error) {
	out := make([]proto.Message, len(nodeEvents))
	for i, e := range nodeEvents {
		out[i] = e
	}
	return out, nil
}

// TestBrokenAgentSubscribeSeesOnlyItsNamespace: whatever filters the agent
// sends, it gets no event from another namespace, and containerd is asked
// only for the agent's.
func TestBrokenAgentSubscribeSeesOnlyItsNamespace(t *testing.T) {
	for _, tc := range []struct {
		name    string
		filters []string
	}{
		{"no filters", nil},
		{"an empty filter", []string{""}},
		{"another namespace by name", []string{`namespace=="k8s.io"`}},
		{"every topic", []string{`topic~=".*"`}},
		{"not the agent's namespace", []string{`namespace!="aerolvm"`}},
		{"the agent's own", []string{`topic~="/tasks/"`, `topic=="/containers/delete"`}},
	} {
		for name, answer := range map[string]responder{"containerd filters": subscribeLikeContainerd, "containerd sends all": sendsAll} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				r := newRig(t, testPolicy())
				r.fake.on(subscribe, answer)
				got, err := r.invoke(nsCtx(), subscribe, &eventsapi.SubscribeRequest{Filters: tc.filters})
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range got {
					if ns := m.(*types.Envelope).GetNamespace(); ns != testNS {
						t.Fatalf("the agent got %s's event %v", ns, m)
					}
				}
				seen := r.fake.seen()
				if len(seen) != 1 {
					t.Fatalf("containerd saw %v", r.fake.methodsSeen())
				}
				fs := seen[0].req.(*eventsapi.SubscribeRequest).GetFilters()
				for _, f := range fs {
					if !strings.HasPrefix(f, `namespace=="aerolvm"`) {
						t.Fatalf("containerd was asked for %q", fs)
					}
				}
				if len(fs) == 0 {
					t.Fatal("containerd was asked with no filter, which is every namespace")
				}
			})
		}
	}
	t.Run("filters that do not parse", func(t *testing.T) {
		r := newRig(t, testPolicy())
		r.fake.on(subscribe, sendsAll)
		_, err := r.invoke(nsCtx(), subscribe, &eventsapi.SubscribeRequest{Filters: []string{`topic==`}})
		r.wantRefused(err, subscribe, string(rootpolicy.RuleNamespace))
	})
}

// TestAgentEventMonitorThroughTheGate: the agent's event monitor, through
// containerd's client library with its own filters, still gets every task
// and container-delete event of its namespace, and nothing else.
func TestAgentEventMonitorThroughTheGate(t *testing.T) {
	for name, answer := range map[string]responder{"containerd filters": subscribeLikeContainerd, "containerd sends all": sendsAll} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, testPolicy())
			r.fake.on(subscribe, answer)
			client, ctx := agentClient(t, r)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			// internal/runtime/containerd events.go StreamEvents.
			envs, errs := client.EventService().Subscribe(ctx, `topic~="/tasks/"`, `topic=="/containers/delete"`)
			var got []string
			for len(got) < 2 {
				select {
				case e := <-envs:
					if e.Namespace != testNS {
						t.Fatalf("the monitor got %s's event %+v", e.Namespace, e)
					}
					got = append(got, e.Topic)
				case err := <-errs:
					t.Fatalf("Subscribe ended after %v: %v", got, err)
				case <-time.After(10 * time.Second):
					t.Fatalf("the monitor got only %v", got)
				}
			}
			if !slices.Equal(got, []string{"/tasks/exit", "/containers/delete"}) {
				t.Fatalf("the monitor got %v", got)
			}
			if refs := r.refused(); len(refs) != 0 {
				t.Fatalf("refused: %+v", refs)
			}
		})
	}
}

// TestKeepOnlyOnServerStreams: an answer the gate drops must be one of a
// stream; dropping a unary call's only answer would leave it unanswered.
func TestKeepOnlyOnServerStreams(t *testing.T) {
	for _, m := range allowlist {
		if m.keep != nil && !m.serverStream {
			t.Fatalf("%s drops answers but is not a server stream", m.name)
		}
	}
}
