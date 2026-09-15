package isolate

import (
	"testing"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

func TestHostSupervisorEgressObserverWiring(t *testing.T) {
	var nilSupervisor *workerdSupervisor
	nilSupervisor.SetEgressObserver(func(string, string, string) {})
	supervisor := NewHostSupervisor(Config{}).(*workerdSupervisor)
	observer := pkgisolate.EgressObserver(func(string, string, string) {})
	supervisor.SetEgressObserver(observer)
	if supervisor.egressObserver == nil {
		t.Fatal("egress observer was not installed")
	}
}
