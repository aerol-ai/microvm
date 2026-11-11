package main

import "testing"

func TestParse(t *testing.T) {
	if _, err := parse(nil); err == nil {
		t.Fatal("no namespace accepted")
	}
	o, err := parse([]string{"--namespace", "aerolvm-system", "--service-account", "aerolvm-operator"})
	if err != nil || o.workerNamespace != "aerolvm-system" || o.templates != "aerolvm-pod-templates" || !o.leaderElect {
		t.Fatalf("defaults = %+v %v", o, err)
	}
	o, err = parse([]string{"--namespace", "a", "--worker-namespace", "b", "--leader-elect=false"})
	if err != nil || o.workerNamespace != "b" || o.leaderElect {
		t.Fatalf("flags = %+v %v", o, err)
	}
	if _, err := parse([]string{"--nope"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if s := newScheme(); !s.IsGroupRegistered("aerolvm.io") {
		t.Fatal("scheme lacks the aerolvm.io group")
	}
}
