package rootpolicy

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// mountSecret is a credential value no rule may ever echo.
const mountSecret = "s3cr3t-VALUE-never-logged"

func goodMounts() map[string]models.MountSpec {
	return map[string]models.MountSpec{
		"s3": {Type: models.MountTypeS3, Target: "/data", Source: "s3://bucket/prefix",
			Options:     map[string]string{"region": "us-east-1", "endpoint": "http://10.0.0.5:9000", "extra_args": "--force-path-style --allow-delete"},
			Credentials: map[string]string{"access_key_id": "minio", "secret_access_key": mountSecret}},
		"nfs": {Type: models.MountTypeNFS, Target: "/share", Source: "10.0.0.9:/export/a",
			Options: map[string]string{"opts": "vers=4.1,soft,timeo=600"}},
		"sshfs": {Type: models.MountTypeSSHFS, Target: "/ssh", Source: "u@host:/srv",
			Credentials: map[string]string{"private_key_pem": mountSecret}},
		"rclone": {Type: models.MountTypeRclone, Target: "/rc", Source: "store:bucket",
			Credentials: map[string]string{"rclone_conf": "[store]\ntype = s3\nprovider = Minio\naccess_key_id = u\nsecret_access_key = " + mountSecret + "\n"}},
	}
}

func TestCheckExternalMounts(t *testing.T) {
	for name, m := range goodMounts() {
		if err := CheckExternalMounts([]models.MountSpec{m}, false, models.MountToolPolicy{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	all := []models.MountSpec{}
	for _, m := range goodMounts() {
		all = append(all, m)
	}
	if err := CheckExternalMounts(all, false, models.MountToolPolicy{}); err != nil {
		t.Fatalf("a set of each: %v", err)
	}

	bad := []struct {
		name   string
		mutate func(*models.MountSpec)
		base   string
	}{
		{"an unknown type", func(m *models.MountSpec) { m.Type = "local" }, "s3"},
		{"a relative target", func(m *models.MountSpec) { m.Target = "data" }, "s3"},
		{"a target with ..", func(m *models.MountSpec) { m.Target = "/data/../etc" }, "s3"},
		{"a reserved target", func(m *models.MountSpec) { m.Target = "/proc" }, "nfs"},
		{"a source read as an option", func(m *models.MountSpec) { m.Source = "-oProxyCommand=x@h:/" }, "sshfs"},
		{"an NFS option off the list", func(m *models.MountSpec) { m.Options["opts"] = "vers=4,helper=/bin/sh" }, "nfs"},
		{"an NFS suid", func(m *models.MountSpec) { m.Options["opts"] = "suid" }, "nfs"},
		{"an extra_arg off the list", func(m *models.MountSpec) { m.Options["extra_args"] = "--log-directory=/etc" }, "s3"},
		{"a cache folder of root's choosing", func(m *models.MountSpec) { m.Options["extra_args"] = "--cache /etc" }, "s3"},
		{"extra_args on NFS", func(m *models.MountSpec) { m.Options["extra_args"] = "--force-path-style" }, "nfs"},
		{"rclone's local backend", func(m *models.MountSpec) { m.Source = ":local:/etc" }, "rclone"},
		{"rclone running a command", func(m *models.MountSpec) {
			m.Credentials["rclone_conf"] = "[store]\ntype = sftp\nhost = h\nssh = /bin/sh -c id\n"
		}, "rclone"},
		{"a credential in extra_args", func(m *models.MountSpec) { m.Options["extra_args"] = "--secret-access-key=" + mountSecret }, "s3"},
		{"a credential as an option key", func(m *models.MountSpec) { m.Options["secret_access_key"] = mountSecret }, "s3"},
		{"an access key id in the source", func(m *models.MountSpec) { m.Source = "s3://AKIAABCDEFGHIJKLMNOP" }, "s3"},
		{"a password in the endpoint", func(m *models.MountSpec) { m.Options["endpoint"] = "https://u:" + mountSecret + "@h" }, "s3"},
		{"a credential in an rclone source", func(m *models.MountSpec) { m.Source = ":s3,secret_access_key=" + mountSecret + ":b" }, "rclone"},
		{"a credential the tool does not read", func(m *models.MountSpec) { m.Credentials["private_key_pem"] = mountSecret }, "s3"},
		{"a credential on NFS", func(m *models.MountSpec) { m.Credentials = map[string]string{"password": mountSecret} }, "nfs"},
		{"a credential name with a newline", func(m *models.MountSpec) { m.Credentials["a\nb"] = mountSecret }, "s3"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneMount(goodMounts()[tc.base])
			tc.mutate(&m)
			err := CheckExternalMounts([]models.MountSpec{m}, false, models.MountToolPolicy{})
			if RuleOf(err) != RuleExternalMount {
				t.Fatalf("got %v, want a %s refusal", err, RuleExternalMount)
			}
			if strings.Contains(err.Error(), mountSecret) {
				t.Fatalf("the refusal carries the credential: %v", err)
			}
		})
	}

	if err := CheckExternalMounts(nil, false, models.MountToolPolicy{}); RuleOf(err) != RuleExternalMount {
		t.Fatalf("no mounts: %v", err)
	}
	many := make([]models.MountSpec, models.MaxMountsPerSandbox+1)
	for i := range many {
		many[i] = goodMounts()["nfs"]
	}
	if err := CheckExternalMounts(many, false, models.MountToolPolicy{}); RuleOf(err) != RuleExternalMount {
		t.Fatalf("too many: %v", err)
	}
	if err := CheckExternalMount(nil, false, models.MountToolPolicy{}); RuleOf(err) != RuleExternalMount {
		t.Fatalf("nil: %v", err)
	}
	if got := printable(strings.Repeat("k", 40) + "\n"); strings.Contains(got, "\n") || len(got) > 40 {
		t.Fatalf("printable: %q", got)
	}
}

// A running mount is held to the lists a running mount may keep: what
// harms nothing while the tool runs passes, and only then.
func TestCheckExternalMountsRunning(t *testing.T) {
	m := cloneMount(goodMounts()["s3"])
	m.Options["extra_args"] = "--debug --max-cache-size 100"
	if err := CheckExternalMounts([]models.MountSpec{m}, false, models.MountToolPolicy{}); err == nil {
		t.Fatal("a create with kept-only flags passed")
	}
	if err := CheckExternalMounts([]models.MountSpec{m}, true, models.MountToolPolicy{}); err != nil {
		t.Fatalf("a running mount with kept flags: %v", err)
	}
	m.Options["extra_args"] = "--log-directory=/etc"
	if err := CheckExternalMounts([]models.MountSpec{m}, true, models.MountToolPolicy{}); RuleOf(err) != RuleExternalMount {
		t.Fatalf("a running mount with a flag that reaches the host: %v", err)
	}
}

// In privilege mode split an s3 mount with no keys would act as the node
// (the helper's tools have no environment of the node's, which leaves the
// instance metadata); rclone's own ways to the node are the allow lists'.
// The operator's setting allows both.
func TestCheckExternalMountsNodeCredentials(t *testing.T) {
	keyless := cloneMount(goodMounts()["s3"])
	keyless.Credentials = nil
	envAuth := models.MountSpec{Type: models.MountTypeRclone, Target: "/rc", Source: ":s3,provider=AWS,env_auth=true:bucket"}
	msi := models.MountSpec{Type: models.MountTypeRclone, Target: "/rc", Source: "a:c",
		Credentials: map[string]string{"rclone_conf": "[a]\ntype = azureblob\naccount = x\nuse_msi = true\n"}}
	for name, m := range map[string]models.MountSpec{"s3 with no keys": keyless, "rclone env_auth": envAuth, "rclone use_msi": msi} {
		err := CheckExternalMounts([]models.MountSpec{m}, false, models.MountToolPolicy{})
		if RuleOf(err) != RuleExternalMount || !strings.Contains(err.Error(), "SB_MOUNTS_ALLOW_NODE_CREDENTIALS") {
			t.Errorf("%s: %v", name, err)
		}
		if err := CheckExternalMounts([]models.MountSpec{m}, false, models.MountToolPolicy{NodeCredentials: true}); err != nil {
			t.Errorf("%s, allowed: %v", name, err)
		}
	}
	anon := keyless
	anon.Options = map[string]string{"extra_args": "--no-sign-request --force-path-style"}
	if err := CheckExternalMounts([]models.MountSpec{anon}, false, models.MountToolPolicy{}); err != nil {
		t.Fatalf("an anonymous s3 mount: %v", err)
	}
}

func cloneMount(m models.MountSpec) models.MountSpec {
	out := m
	out.Options = map[string]string{}
	for k, v := range m.Options {
		out.Options[k] = v
	}
	out.Credentials = map[string]string{}
	for k, v := range m.Credentials {
		out.Credentials[k] = v
	}
	return out
}

func TestMountPoint(t *testing.T) {
	if p, err := MountPoint("/var/lib/aerolvm-rootd/mounts", "sb-1", 3); err != nil || p != "/var/lib/aerolvm-rootd/mounts/sb-1/3" {
		t.Fatalf("%q %v", p, err)
	}
	for _, tc := range []struct {
		root, id string
		index    int
	}{
		{"mounts", "sb-1", 0}, {"/", "sb-1", 0}, {"/m/", "sb-1", 0}, {"/m/../x", "sb-1", 0},
		{"/m", "", 0}, {"/m", "..", 0}, {"/m", "a/b", 0}, {"/m", "sb-1/../sb-2", 0}, {"/m", "sb 1", 0},
		{"/m", "sb-1", -1}, {"/m", "sb-1", models.MaxMountsPerSandbox},
	} {
		if p, err := MountPoint(tc.root, tc.id, tc.index); RuleOf(err) != RuleExternalMount {
			t.Errorf("%+v: %q %v", tc, p, err)
		}
	}
}

func TestCheckMountBind(t *testing.T) {
	const root = "/var/lib/aerolvm-rootd/mounts"
	for i := range models.MaxMountsPerSandbox {
		if err := CheckMountBind(root, "sb-1", root+"/sb-1/"+strconv.Itoa(i)); err != nil {
			t.Fatalf("mount point %d: %v", i, err)
		}
	}
	for _, src := range []string{
		root + "/sb-2/0",     // another sandbox's mount
		root + "/sb-1",       // the sandbox's folder: its tools' logs
		root + "/sb-1/0.log", // a tool's log
		root + "/sb-1/8",     // past the last index
		root + "/sb-1/00",    // not how an index is written
		root + "/sb-1/+1",
		root + "/sb-1/0/x", // inside a mount
		"/elsewhere/sb-1/0",
		root,
	} {
		if err := CheckMountBind(root, "sb-1", src); RuleOf(err) != RuleMount {
			t.Errorf("%s: %v", src, err)
		}
	}
}

// The gate's spec check holds every bind from the mounts folder to the
// container's own mount points; other bind roots keep their rule.
func TestCheckSpecMountBinds(t *testing.T) {
	p := testPolicy()
	p.MountsRoot = testMounts
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	bind := func(src string) *specs.Spec {
		s := baselineSpec(t)
		s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: src, Destination: "/data", Options: []string{"rbind"}})
		return s
	}
	if err := CheckSpec(p, testID, bind(testMounts+"/"+testID+"/0")); err != nil {
		t.Fatalf("its own mount: %v", err)
	}
	for _, src := range []string{testMounts + "/sb-2/0", testMounts + "/" + testID, testMounts + "/" + testID + "/0.log"} {
		if err := CheckSpec(p, testID, bind(src)); RuleOf(err) != RuleMount {
			t.Errorf("%s: %v", src, err)
		}
	}
	// Without MountsRoot (a policy from before), a bind root's rule alone.
	if err := CheckSpec(testPolicy(), testID, bind(testMounts+"/sb-2/0")); err != nil {
		t.Fatalf("no mounts root: %v", err)
	}
	bad := testPolicy()
	bad.MountsRoot = "/var/lib/elsewhere"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "mounts root") {
		t.Fatalf("a mounts root that is no bind root: %v", err)
	}
}

func TestCheckMountSandboxID(t *testing.T) {
	if err := CheckMountSandboxID("sb_1-A"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", ".", "..", "a/b", "a\x00", strings.Repeat("a", 129)} {
		if err := CheckMountSandboxID(id); RuleOf(err) != RuleExternalMount {
			t.Errorf("%q: %v", id, err)
		}
	}
}

// FuzzCheckExternalMount: whatever spec the fuzzer finds, one the rules
// let through builds a command whose last word is its mount point, whose
// source and mount point follow "--", where no word after the tool's
// name carries a credential's value, and a refusal names its rule and
// never carries a credential.
func FuzzCheckExternalMount(f *testing.F) {
	for _, m := range goodMounts() {
		f.Add(string(m.Type), m.Target, m.Source, m.Options["opts"], m.Options["extra_args"], m.Options["region"], "secret_access_key", mountSecret)
	}
	f.Add("s3", "/d", "b", "", "--cache /etc", "", "access_key_id", mountSecret)
	f.Add("rclone", "/d", ":local:/", "", "", "", "rclone_conf", "[x]\ntype=local\n")
	f.Add("sshfs", "/d", "-oProxyCommand=id@h:/", "", "", "", "private_key_pem", mountSecret)
	f.Fuzz(func(t *testing.T, typ, target, source, opts, extra, region, credKey, credVal string) {
		m := models.MountSpec{Type: models.MountType(typ), Target: target, Source: source,
			Options: map[string]string{}, Credentials: map[string]string{credKey: credVal}}
		for k, v := range map[string]string{"opts": opts, "extra_args": extra, "region": region} {
			if v != "" {
				m.Options[k] = v
			}
		}
		err := CheckExternalMount(&m, false, models.MountToolPolicy{})
		secret := len(credVal) >= 12 && !strings.Contains(typ+target+source+opts+extra+region+credKey, credVal)
		if err != nil {
			if RuleOf(err) != RuleExternalMount {
				t.Fatalf("refusal names no rule: %v", err)
			}
			if secret && strings.Contains(err.Error(), credVal) {
				t.Fatalf("the refusal carries the credential: %v", err)
			}
			return
		}
		host, perr := MountPoint("/m", "sb-1", 0)
		if perr != nil {
			t.Fatal(perr)
		}
		plan, berr := adapters.Adapters()[m.Type].Build("sb-1", 0, m, host, "/creds")
		if berr != nil {
			return // a spec a tool cannot use (an rclone remote with no config) fails, never runs
		}
		argv := plan.Argv
		if argv[len(argv)-1] != host {
			t.Fatalf("argv does not end with the mount point: %q", argv)
		}
		end := -1
		for i, a := range argv {
			if a == "--" {
				end = i
			}
		}
		if end < 0 || end != len(argv)-3 {
			t.Fatalf("source and mount point are not alone after --: %q", argv)
		}
		if strings.HasPrefix(argv[end+1], "-") {
			t.Fatalf("a source a tool reads as an option: %q", argv)
		}
		if strings.TrimSpace(credVal) != "" {
			// The same spec with another credential builds the same
			// command and environment: no credential reaches either.
			other := m
			other.Credentials = map[string]string{credKey: "zzzzzzzzzzzz"}
			plan2, err := adapters.Adapters()[m.Type].Build("sb-1", 0, other, host, "/creds")
			if err != nil || !slices.Equal(plan.Argv, plan2.Argv) || !slices.Equal(plan.Env, plan2.Env) {
				t.Fatalf("a credential reaches the command line or the environment: %q %q", plan.Argv, plan.Env)
			}
		}
	})
}

// FuzzMountPoint: a mount point the rule builds is two names below its
// root, and is exactly the one the gate lets that sandbox bind.
func FuzzMountPoint(f *testing.F) {
	f.Add("/m", "sb-1", 0)
	f.Add("/m", "../x", 1)
	f.Add("/m/", "sb", 9)
	f.Fuzz(func(t *testing.T, root, id string, index int) {
		p, err := MountPoint(root, id, index)
		if err != nil {
			if RuleOf(err) != RuleExternalMount {
				t.Fatalf("refusal names no rule: %v", err)
			}
			return
		}
		rest, ok := strings.CutPrefix(p, root+"/")
		if !ok || strings.Count(rest, "/") != 1 || !cleanAbs(p) {
			t.Fatalf("%q is not two names below %q", p, root)
		}
		if err := CheckMountBind(root, id, p); err != nil {
			t.Fatalf("the gate refuses the sandbox's own mount point %q: %v", p, err)
		}
		if id != "other" {
			if err := CheckMountBind(root, "other", p); err == nil {
				t.Fatalf("another container may bind %q", p)
			}
		}
	})
}

// FuzzCheckMountBind: a bind the gate lets through is exactly one of the
// container's mount points.
func FuzzCheckMountBind(f *testing.F) {
	f.Add("sb-1", "/m/sb-1/0")
	f.Add("sb-1", "/m/sb-2/0")
	f.Add("sb-1", "/m/sb-1/0/../../sb-2/0")
	f.Fuzz(func(t *testing.T, id, src string) {
		if CheckMountBind("/m", id, src) != nil {
			return
		}
		ok := false
		for i := range models.MaxMountsPerSandbox {
			if src == "/m/"+id+"/"+strconv.Itoa(i) {
				ok = true
			}
		}
		if !ok || strings.Contains(id, "/") {
			t.Fatalf("%q passed for %q", src, id)
		}
	})
}
