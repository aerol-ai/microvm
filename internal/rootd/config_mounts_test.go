package rootd

import (
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestMountsFromEnv: the mount tools' user and folders come from the
// helper's own environment; the user must be one nothing else runs as.
func TestMountsFromEnv(t *testing.T) {
	const agent = 65531
	get := func(m map[string]string) func(string) string { return env(m) }
	m, err := mountsFromEnv(get(map[string]string{"SB_ROOTD_MOUNT_USER": "65520:65521", "SB_MOUNT_WAIT_TIMEOUT": "45s",
		"SB_CONTAINERD_CGROUP_PARENT": "/aerolvm.slice", "SB_MOUNTS_ALLOW_NODE_CREDENTIALS": "true"}), agent, "/m", "/c", "/k")
	if err != nil {
		t.Fatal(err)
	}
	want := MountsConfig{Root: "/m", CredDir: "/c", CacheDir: "/k", UID: 65520, GID: 65521,
		CgroupRoot: "/sys/fs/cgroup/aerolvm.slice", WaitTimeout: 45 * time.Second, NodeCredentials: true}
	if *m != want {
		t.Fatalf("%+v, want %+v", *m, want)
	}
	m, err = mountsFromEnv(get(map[string]string{"SB_ROOTD_MOUNT_USER": "65520", "SB_HOST_PROCESS_CGROUP_PARENT": "/k/sb"}), agent, "/m", "/c", "/k")
	if err != nil || m.GID != 65520 || m.CgroupRoot != "/sys/fs/cgroup/k/sb" || m.WaitTimeout != 30*time.Second || m.NodeCredentials {
		t.Fatalf("%+v %v", m, err)
	}
	// No setting and no such user on this node: no mounts, no error.
	if _, err := user.Lookup(DefaultMountUser); err != nil {
		if m, err := mountsFromEnv(get(nil), agent, "/m", "/c", "/k"); m != nil || err != nil {
			t.Fatalf("no mount user: %+v %v", m, err)
		}
	}
	// A user by name: this test's own, when it is not root.
	if u, err := user.Current(); err == nil && u.Gid != "0" && !slices.Contains([]string{"0", "1000", "65531", "65532", "65534"}, u.Uid) {
		m, err := mountsFromEnv(get(map[string]string{"SB_ROOTD_MOUNT_USER": u.Username}), agent, "/m", "/c", "/k")
		if err != nil || strconv.Itoa(int(m.UID)) != u.Uid {
			t.Fatalf("by name: %+v %v", m, err)
		}
	}
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"SB_ROOTD_MOUNT_USER": "0"}, "must not run as root"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65520:0"}, "must not run as root"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65531"}, "the agent's"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65534"}, "nobody"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65532"}, "egress gateway"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "1000"}, "SB_ISOLATE_JAIL_UID"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65520:x"}, "uid:gid"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "name:65520"}, "uid:gid"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "no-such-user-aerolvm"}, "SB_ROOTD_MOUNT_USER"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65520", "SB_MOUNT_WAIT_TIMEOUT": "soon"}, "SB_MOUNT_WAIT_TIMEOUT"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65520", "SB_MOUNT_WAIT_TIMEOUT": "0s"}, "SB_MOUNT_WAIT_TIMEOUT"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65520", "SB_MOUNTS_ALLOW_NODE_CREDENTIALS": "perhaps"}, "SB_MOUNTS_ALLOW_NODE_CREDENTIALS"},
		{map[string]string{"SB_ROOTD_MOUNT_USER": "65520", "SB_JAILER_UID": "-1"}, "not a uid"},
	} {
		if _, err := mountsFromEnv(get(tc.env), agent, "/m", "/c", "/k"); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.env, err, tc.want)
		}
	}
}

// TestConfigFromEnvMounts: the mount folders are the helper's own, the
// policy binds from that one, and none may sit in the agent's folders.
func TestConfigFromEnvMounts(t *testing.T) {
	stubHost(t, 1024, nil)
	gid := strconv.Itoa(os.Getgid())
	cfg, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ROOTD_MOUNT_USER": "65520"}))
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Mounts
	if m == nil || m.Root != "/var/lib/aerolvm-rootd/mounts" || m.CredDir != DefaultMountCredDir || m.CacheDir != "/var/lib/aerolvm-rootd/mountcache" ||
		cfg.Policy.MountsRoot != m.Root {
		t.Fatalf("mounts %+v, policy root %s", m, cfg.Policy.MountsRoot)
	}
	for _, tc := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"SB_ROOTD_MOUNTS_DIR": "/var/lib/sandboxd/mounts"}, "SB_ROOTD_MOUNTS_DIR"},
		{map[string]string{"SB_ROOTD_MOUNT_CRED_DIR": "/run/sandboxd/keys"}, "SB_ROOTD_MOUNT_CRED_DIR"},
		{map[string]string{"SB_ROOTD_MOUNTS_DIR": "mounts"}, "want an absolute path"},
		{map[string]string{"SB_ROOTD_MOUNTS_DIR": "/var/lib/aerolvm-rootd/hosts/m"}, "overlap"},
		{map[string]string{"SB_ROOTD_MOUNT_CRED_DIR": "/run/aerolvm-rootd/fifo/k"}, "overlap"},
	} {
		e := map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ROOTD_MOUNT_USER": "65520", "SB_HOST_MEMORY_MB": "1"}
		for k, v := range tc.env {
			e[k] = v
		}
		if _, err := ConfigFromEnv(env(e)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.env, err, tc.want)
		}
	}
	// The mounts folder must be the policy's mounts root, and a config
	// needs a user other than root's and a wait.
	bad := cfg
	bad.Mounts = &MountsConfig{Root: "/elsewhere", CredDir: "/c", CacheDir: "/k", UID: 1, GID: 1, WaitTimeout: time.Second}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "mounts root") {
		t.Fatalf("another root: %v", err)
	}
	bad.Mounts = &MountsConfig{Root: cfg.Policy.MountsRoot, CredDir: "/c", CacheDir: "/k"}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "other than root") {
		t.Fatalf("no user: %v", err)
	}
	bad.Mounts = &MountsConfig{Root: cfg.Policy.MountsRoot, CredDir: "c", CacheDir: "/k", UID: 1, GID: 1, WaitTimeout: time.Second}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "clean absolute") {
		t.Fatalf("a relative folder: %v", err)
	}
	bad.Mounts = &MountsConfig{Root: cfg.Policy.MountsRoot, CredDir: cfg.Policy.MountsRoot + "/k", CacheDir: "/k", UID: 1, GID: 1, WaitTimeout: time.Second}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("keys in the mounts folder: %v", err)
	}
}

// TestReclaimFromEnv: platform volume reclaim is the helper's only on an
// NFS backend, from its own settings, checked as sandboxd checks them.
func TestReclaimFromEnv(t *testing.T) {
	for _, off := range []map[string]string{nil, {"SB_PLATFORM_VOLUMES_ENABLED": "false", "SB_PLATFORM_VOLUMES_BACKEND": "nfs"},
		{"SB_PLATFORM_VOLUMES_ENABLED": "true", "SB_PLATFORM_VOLUMES_BACKEND": "s3"}} {
		if rc, err := reclaimFromEnv(env(off), "/s"); rc != nil || err != nil {
			t.Fatalf("%v: %+v %v", off, rc, err)
		}
	}
	on := map[string]string{"SB_PLATFORM_VOLUMES_ENABLED": "true", "SB_PLATFORM_VOLUMES_BACKEND": "NFS",
		"SB_PLATFORM_VOLUMES_NFS_SERVER": "10.0.0.9", "SB_PLATFORM_VOLUMES_NFS_EXPORT": "/exports/vols", "SB_PLATFORM_VOLUMES_NFS_OPTIONS": "vers=4.1"}
	rc, err := reclaimFromEnv(env(on), "/s")
	if err != nil || rc.Export != (rootpolicy.NFSExport{Server: "10.0.0.9", Export: "/exports/vols"}) || rc.Options != "vers=4.1" || rc.ScratchDir != "/s" {
		t.Fatalf("%+v %v", rc, err)
	}
	for k, v := range map[string]string{"SB_PLATFORM_VOLUMES_NFS_SERVER": "", "SB_PLATFORM_VOLUMES_NFS_EXPORT": "/",
		"SB_PLATFORM_VOLUMES_NFS_OPTIONS": "helper=/bin/sh", "SB_PLATFORM_VOLUMES_ENABLED": "sure"} {
		e := map[string]string{}
		for a, b := range on {
			e[a] = b
		}
		e[k] = v
		if _, err := reclaimFromEnv(env(e), "/s"); err == nil {
			t.Errorf("%s=%q passed", k, v)
		}
	}
	stubHost(t, 1024, nil)
	on["SB_ROOTD_SOCKET_GROUP"] = strconv.Itoa(os.Getgid())
	cfg, err := ConfigFromEnv(env(on))
	if err != nil || cfg.Reclaim == nil || cfg.Reclaim.ScratchDir != filepath.Join(DefaultStateDir, "reclaim") {
		t.Fatalf("%+v %v", cfg.Reclaim, err)
	}
	on["SB_PLATFORM_VOLUMES_NFS_OPTIONS"] = "suid"
	if _, err := ConfigFromEnv(env(on)); err == nil {
		t.Fatal("refused NFS options passed")
	}
}
