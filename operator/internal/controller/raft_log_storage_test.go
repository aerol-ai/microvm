package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/aerol-ai/microvm/operator/api/v1alpha1"
)

func claim(name string, annotations map[string]string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: testNS, Name: name, Annotations: annotations}}
}

func getClaim(t *testing.T, cl client.Client, name string) *corev1.PersistentVolumeClaim {
	t.Helper()
	var pvc corev1.PersistentVolumeClaim
	err := cl.Get(context.Background(), types.NamespacedName{Namespace: testNS, Name: name}, &pvc)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return &pvc
}

// A server's claims are laid out once, when it is made, and kept: its data
// claim names its log claim, a server made before servers.logStorage keeps
// its log on the data disk, an old log claim is never taken by a new
// server, and a log claim the operator did not get to make is made on the
// next pass.
func TestEnsurePVCLaysOutTheRaftLogOnce(t *testing.T) {
	class := "io2"
	logStorage := &v1.StorageSpec{Size: resource.MustParse("10Gi"), StorageClassName: &class}
	const node = "prod-server-0"
	for _, tc := range []struct {
		name       string
		logStorage *v1.StorageSpec
		have       []client.Object
		wantErr    string
		wantLog    bool // the data claim names the log claim, which exists
		wantNoLog  bool // no log claim exists
	}{
		{name: "no log storage", wantNoLog: true},
		{name: "log storage", logStorage: logStorage, wantLog: true},
		{name: "a server made before log storage keeps its layout", logStorage: logStorage,
			have: []client.Object{claim(PVCName(node), nil)}, wantNoLog: true},
		{name: "an old log claim is not taken", logStorage: logStorage,
			have: []client.Object{claim(LogPVCName(node), nil)}, wantErr: "holds an old Raft log"},
		{name: "a log claim not made yet is made", logStorage: logStorage,
			have: []client.Object{claim(PVCName(node), map[string]string{AnnotationLogClaim: LogPVCName(node)})}, wantLog: true},
		{name: "a log claim gone with log storage cleared", logStorage: nil,
			have: []client.Object{claim(PVCName(node), map[string]string{AnnotationLogClaim: LogPVCName(node)})}, wantErr: "is gone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testCluster()
			c.Spec.Servers.LogStorage = tc.logStorage
			r, _, cl := clusterRig(t, c, tc.have...)
			err := r.ensurePVC(context.Background(), c, node)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ensurePVC = %v; want %q", err, tc.wantErr)
				}
				if tc.name == "an old log claim is not taken" && getClaim(t, cl, PVCName(node)) != nil {
					t.Fatal("a data claim was made beside an old log claim")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, log := getClaim(t, cl, PVCName(node)), getClaim(t, cl, LogPVCName(node))
			if data == nil {
				t.Fatal("no data claim")
			}
			if tc.wantNoLog && (log != nil || data.Annotations[AnnotationLogClaim] != "") {
				t.Fatalf("log claim %v, annotations %v; want none", log, data.Annotations)
			}
			if tc.wantLog {
				if log == nil || data.Annotations[AnnotationLogClaim] != LogPVCName(node) {
					t.Fatalf("log claim %v, annotations %v", log, data.Annotations)
				}
				if got := log.Spec.Resources.Requests[corev1.ResourceStorage]; got.Cmp(logStorage.Size) != 0 ||
					log.Spec.StorageClassName == nil || *log.Spec.StorageClassName != class {
					t.Fatalf("log claim spec %+v; want 10Gi of %s", log.Spec, class)
				}
				if len(log.OwnerReferences) != 0 {
					t.Fatal("a log claim has an owner: deleting it would delete the log")
				}
			}
			// Again: nothing changes.
			if err := r.ensurePVC(context.Background(), c, node); err != nil {
				t.Fatalf("second ensurePVC: %v", err)
			}
		})
	}
}

// A server whose data claim names a log claim gets it mounted in sandboxd's
// container, outside the state volume, with SB_RAFT_WAL_DIR on a folder of
// it; one with no log claim gets neither; and no server pod is made before
// its data claim shows, since that pod would put its log on the data disk.
func TestServerPodMountsItsRaftLogClaim(t *testing.T) {
	t.Run("named", func(t *testing.T) {
		g := newNodeRig(t, testCluster(), node("prod-server-0", v1.RoleServer, "", "z-a"), machine("m1"),
			claim(PVCName("prod-server-0"), map[string]string{AnnotationLogClaim: LogPVCName("prod-server-0")}))
		g.reconcile("prod-server-0")
		p := g.pod(testNS, "prod-server-0")
		if p == nil {
			t.Fatal("no pod")
		}
		var vol *corev1.Volume
		for i := range p.Spec.Volumes {
			if p.Spec.Volumes[i].Name == RaftLogVolume {
				vol = &p.Spec.Volumes[i]
			}
		}
		if vol == nil || vol.PersistentVolumeClaim == nil || vol.PersistentVolumeClaim.ClaimName != LogPVCName("prod-server-0") {
			t.Fatalf("raft-log volume %+v", vol)
		}
		agent := p.Spec.Containers[containerIndex(p.Spec.Containers, AgentContainer)]
		mounted, env := false, ""
		for _, m := range agent.VolumeMounts {
			if m.Name == RaftLogVolume && m.MountPath == "/var/lib/aerolvm-raft-log" {
				mounted = true
			}
		}
		for _, e := range agent.Env {
			if e.Name == "SB_RAFT_WAL_DIR" {
				env = e.Value
			}
		}
		if !mounted || env != "/var/lib/aerolvm-raft-log/raft-wal" {
			t.Fatalf("agent mount %v, SB_RAFT_WAL_DIR %q", mounted, env)
		}
		for _, m := range p.Spec.InitContainers[0].VolumeMounts {
			if m.Name == RaftLogVolume {
				t.Fatal("setup mounts the Raft log")
			}
		}
	})
	t.Run("none", func(t *testing.T) {
		g := newNodeRig(t, testCluster(), node("prod-server-0", v1.RoleServer, "", "z-a"), machine("m1"))
		g.reconcile("prod-server-0")
		p := g.pod(testNS, "prod-server-0")
		if p == nil {
			t.Fatal("no pod")
		}
		for _, v := range p.Spec.Volumes {
			if v.Name == RaftLogVolume {
				t.Fatal("a raft-log volume with no log claim")
			}
		}
		for _, e := range p.Spec.Containers[containerIndex(p.Spec.Containers, AgentContainer)].Env {
			if e.Name == "SB_RAFT_WAL_DIR" {
				t.Fatal("SB_RAFT_WAL_DIR with no log claim")
			}
		}
	})
	t.Run("no data claim yet", func(t *testing.T) {
		g := newNodeRig(t, testCluster(), node("prod-server-0", v1.RoleServer, "", "z-a"), machine("m1"))
		if err := g.cl.Delete(context.Background(), claim(PVCName("prod-server-0"), nil)); err != nil {
			t.Fatal(err)
		}
		res := g.reconcile("prod-server-0")
		if g.pod(testNS, "prod-server-0") != nil || res.RequeueAfter == 0 {
			t.Fatalf("a pod before its data claim, requeue %v", res.RequeueAfter)
		}
		if n := g.node("prod-server-0"); n.Status.State != v1.StatePending || !strings.Contains(n.Status.Reason, "volume claim") {
			t.Fatalf("state %q %q", n.Status.State, n.Status.Reason)
		}
	})
}
