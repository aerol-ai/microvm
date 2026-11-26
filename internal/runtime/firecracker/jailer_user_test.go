package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A host's user and group files, as a common cloud image ships them plus
// the users the installers make.
const (
	testPasswd = `root:x:0:0:root:/root:/bin/bash
# a comment line
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
broken line with no fields
alsobroken:x:notanumber:1::/:/bin/sh
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
ec2-user:x:1001:1001:EC2 Default User:/home/ec2-user:/bin/bash
sandboxd:x:997:997::/var/lib/sandboxd:/usr/sbin/nologin
sandboxd-jailer:x:996:996::/home/sandboxd-jailer:/usr/sbin/nologin
plainlogin:x:2000:2000::/home/plainlogin:/bin/bash
emptyshell:x:2001:2001::/home/emptyshell:
falseshell:x:2002:2002::/:/bin/false
dockeruser:x:2003:2003::/:/usr/sbin/nologin
wheelprimary:x:2004:10::/:/sbin/nologin
quiet1000:x:3000:3000::/:/usr/sbin/nologin
`
	testGroup = `root:x:0:
wheel:x:10:ec2-user
sudo:x:27:ubuntu
adm:x:4:syslog,ubuntu
lxd:x:110:ubuntu
docker:x:999:dockeruser
admin:x:115:
ubuntu:x:1000:
ec2-user:x:1001:
sandboxd:x:997:
sandboxd-jailer:x:996:
plainlogin:x:2000:
dockeruser:x:2003:
bad:x:nope:
short:x
`
)

func writeUserFiles(t *testing.T) (passwd, group string) {
	t.Helper()
	dir := t.TempDir()
	passwd, group = filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte(testPasswd), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte(testGroup), 0o644); err != nil {
		t.Fatal(err)
	}
	return passwd, group
}

func TestCheckJailerUser(t *testing.T) {
	passwd, group := writeUserFiles(t)
	for _, tc := range []struct {
		name     string
		uid, gid int
		agent    int      // sandboxd's uid: 0 (root) in single mode
		want     []string // each must be in the error; nil is no error
	}{
		{name: "installers' sandboxd-jailer", uid: 996, gid: 996},
		{name: "a uid with no user, as the Kubernetes chart's", uid: 990, gid: 990},
		{name: "a quiet user of its own keeps working", uid: 3000, gid: 3000},
		{name: "a false shell is no login", uid: 2002, gid: 2002},
		{name: "split: a user other than sandboxd's", uid: 996, gid: 996, agent: 997},

		{name: "root", uid: 0, gid: 996, want: []string{"uid 0 is root"}},
		{name: "root's group", uid: 996, gid: 0, want: []string{"gid 0 is root's group"}},
		{name: "split: sandboxd's own user", uid: 997, gid: 997, agent: 997, want: []string{"uid 997 is sandboxd's own user"}},
		{name: "Ubuntu's login user", uid: 1000, gid: 1000, want: []string{
			"SB_JAILER_UID=1000 SB_JAILER_GID=1000", "the user ubuntu, in the sudo group", "the user ubuntu, in the lxd group",
			"the user ubuntu, with the login shell /bin/bash", "useradd --system", "SB_JAILER_UID and SB_JAILER_GID"}},
		{name: "Amazon Linux's login user", uid: 1001, gid: 1001, want: []string{"the user ec2-user, in the wheel group", "login shell /bin/bash"}},
		{name: "a login shell alone", uid: 2000, gid: 2000, want: []string{"the user plainlogin, with the login shell /bin/bash"}},
		{name: "an empty shell is /bin/sh", uid: 2001, gid: 2001, want: []string{"the user emptyshell, with the login shell /bin/sh (no shell set)"}},
		{name: "the docker group", uid: 2003, gid: 2003, want: []string{"the user dockeruser, in the docker group"}},
		{name: "wheel as the primary group", uid: 2004, gid: 2004, want: []string{"the user wheelprimary, in the wheel group"}},
		{name: "the sudo group as the jailer's group", uid: 990, gid: 27, want: []string{"gid 27 is the sudo group"}},
		{name: "the admin group as the jailer's group", uid: 990, gid: 115, want: []string{"gid 115 is the admin group"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckJailerUser(JailerUserCheck{UID: tc.uid, GID: tc.gid, AgentUID: tc.agent, PasswdPath: passwd, GroupPath: group})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("passed, want an error naming %q", tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q\ndoes not say %q", err, w)
				}
			}
		})
	}
}

// A host with no uid 1000 (the old default) still starts: an upgrade does
// not stop a node whose uid 1000 is nobody.
func TestCheckJailerUserOldDefaultWithNoUser(t *testing.T) {
	dir := t.TempDir()
	passwd, group := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("root:x:0:\nsudo:x:27:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckJailerUser(JailerUserCheck{UID: 1000, GID: 1000, PasswdPath: passwd, GroupPath: group}); err != nil {
		t.Fatalf("refused uid 1000 with no user: %v", err)
	}
}

// No user or group file (a bare container image) is no users and no groups.
// A file that cannot be read stops the start with the setting named.
func TestCheckJailerUserFiles(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if err := CheckJailerUser(JailerUserCheck{UID: 990, GID: 990, PasswdPath: missing, GroupPath: missing}); err != nil {
		t.Fatalf("missing files: %v", err)
	}
	passwd, group := writeUserFiles(t)
	for name, c := range map[string]JailerUserCheck{
		"passwd": {UID: 990, GID: 990, PasswdPath: dir, GroupPath: group},
		"group":  {UID: 990, GID: 990, PasswdPath: passwd, GroupPath: dir},
	} {
		err := CheckJailerUser(c)
		if err == nil || !strings.Contains(err.Error(), "check the jailer's user (SB_JAILER_UID=990)") {
			t.Errorf("%s file is a folder: %v", name, err)
		}
	}
	if _, err := readPasswd(filepath.Join(dir, "nope")); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		closed := filepath.Join(dir, "closed")
		if err := os.WriteFile(closed, []byte(testPasswd), 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := readPasswd(closed); err == nil {
			t.Fatal("a user file sandboxd cannot open read as no users")
		}
	}
	// A line too long for the scanner is an error, not a silent stop.
	long := filepath.Join(dir, "long")
	if err := os.WriteFile(long, []byte(strings.Repeat("x", 70*1024)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGroup(long); err == nil {
		t.Fatal("a line past the scanner's limit read as nothing")
	}
}
