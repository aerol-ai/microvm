package firecracker

// jailer_user.go checks, once at sandboxd's start, the user the jailer runs
// every VM as (SB_JAILER_UID / SB_JAILER_GID). All VMs on a node share that
// one user, and it owns each VM's own files, so it should be a system user
// of its own that nothing else uses or logs in as. install.sh
// --with-firecracker, the Terraform bootstrap and Ansible's configure-ops.yml
// make one, sandboxd-jailer. Older installs and the config default use uid
// 1000, which on many cloud images is the login user; sandboxd keeps such a
// setting as it is (it never picks another uid by itself) and refuses to
// start until the operator points the jailer at a user of its own.

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// JailerUserCheck is what CheckJailerUser looks at.
type JailerUserCheck struct {
	// UID and GID are SB_JAILER_UID and SB_JAILER_GID.
	UID, GID int
	// AgentUID is sandboxd's own uid: root in privilege mode single,
	// sandboxd's user in split.
	AgentUID int
	// PasswdPath and GroupPath are the host's user and group files,
	// /etc/passwd and /etc/group.
	PasswdPath, GroupPath string
}

// adminGroups are the groups whose members can become root, or do as much
// through a daemon (docker, lxd): sudo on Debian and Ubuntu, wheel on
// Amazon Linux and Fedora, admin on older Ubuntu.
var adminGroups = map[string]bool{"root": true, "sudo": true, "wheel": true, "admin": true, "docker": true, "lxd": true}

// noLoginShells are the shells that refuse a login (by base name).
var noLoginShells = map[string]bool{"nologin": true, "false": true, "true": true}

// JailerUserFix is how an operator gives the jailer a user of its own.
const JailerUserFix = "make a system user for it and point sandboxd at that user, then restart sandboxd: " +
	"`useradd --system --no-create-home --shell /usr/sbin/nologin --user-group sandboxd-jailer`, " +
	"then set SB_JAILER_UID and SB_JAILER_GID to `id -u sandboxd-jailer` and `id -g sandboxd-jailer` " +
	"in /etc/sandboxd/sandboxd.env (in /etc/sandboxd/cluster.env where that file sets them). " +
	"install.sh --with-firecracker and Ansible's configure-ops.yml do this for you"

// CheckJailerUser refuses a jailer user that is not one of its own: root or
// root's group, sandboxd's own user, a user with a login shell, or a user
// or group that is (or is in) an admin group. A uid with no entry in the
// user file is a user of its own (the Kubernetes chart's 990 is one). The
// error names the settings and how to fix them.
func CheckJailerUser(c JailerUserCheck) error {
	users, err := readPasswd(c.PasswdPath)
	if err != nil {
		return fmt.Errorf("firecracker: check the jailer's user (SB_JAILER_UID=%d): %w", c.UID, err)
	}
	groups, err := readGroup(c.GroupPath)
	if err != nil {
		return fmt.Errorf("firecracker: check the jailer's user (SB_JAILER_UID=%d): %w", c.UID, err)
	}
	var why []string
	if c.UID == 0 {
		why = append(why, "uid 0 is root")
	} else if c.UID == c.AgentUID {
		why = append(why, fmt.Sprintf("uid %d is sandboxd's own user", c.UID))
	}
	if c.GID == 0 {
		why = append(why, "gid 0 is root's group")
	}
	for _, g := range groups {
		if adminGroups[g.name] && g.gid == c.GID && c.GID != 0 {
			why = append(why, fmt.Sprintf("gid %d is the %s group", c.GID, g.name))
		}
	}
	for _, u := range users {
		if u.uid != c.UID || c.UID == 0 {
			continue
		}
		for _, g := range groups {
			if adminGroups[g.name] && (g.gid == u.gid || g.members[u.name]) {
				why = append(why, fmt.Sprintf("uid %d is the user %s, in the %s group", c.UID, u.name, g.name))
			}
		}
		if !noLoginShells[filepath.Base(u.shell)] {
			shell := u.shell
			if shell == "" {
				shell = "/bin/sh (no shell set)"
			}
			why = append(why, fmt.Sprintf("uid %d is the user %s, with the login shell %s", c.UID, u.name, shell))
		}
	}
	if len(why) == 0 {
		return nil
	}
	return fmt.Errorf("firecracker: SB_JAILER_UID=%d SB_JAILER_GID=%d: %s. The jailer runs every VM as this user, "+
		"so it must be a system user of its own: not root or sandboxd's user, no login shell, "+
		"and not in a group that gives root rights (root, sudo, wheel, admin, docker, lxd). To fix it, %s",
		c.UID, c.GID, strings.Join(why, "; "), JailerUserFix)
}

type passwdEntry struct {
	name     string
	uid, gid int
	shell    string
}

type groupEntry struct {
	name    string
	gid     int
	members map[string]bool
}

// readPasswd reads name:x:uid:gid:gecos:home:shell lines. A missing file is
// no users (a container image may have none), a line it cannot read is
// skipped, as getpwent does.
func readPasswd(path string) ([]passwdEntry, error) {
	var out []passwdEntry
	err := eachLine(path, func(f []string) {
		if len(f) < 7 {
			return
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			return
		}
		out = append(out, passwdEntry{name: f[0], uid: uid, gid: gid, shell: f[6]})
	})
	return out, err
}

// readGroup reads name:x:gid:member,member lines, like readPasswd.
func readGroup(path string) ([]groupEntry, error) {
	var out []groupEntry
	err := eachLine(path, func(f []string) {
		if len(f) < 4 {
			return
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			return
		}
		g := groupEntry{name: f[0], gid: gid, members: map[string]bool{}}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.members[m] = true
			}
		}
		out = append(out, g)
	})
	return out, err
}

// eachLine calls fn with the colon-separated fields of each line of path
// that is not empty or a comment.
func eachLine(path string, fn func([]string)) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fn(strings.Split(line, ":"))
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}
