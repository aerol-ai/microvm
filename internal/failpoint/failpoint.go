// Package failpoint lets the live integration suite stop sandboxd at one
// exact point in a request, so a crash can land where a real one would do
// the most damage instead of wherever a SIGKILL from outside happens to fall.
//
// It is compiled in only under the itest_failpoints build tag, which nothing
// but integration-tests/lib/build.sh sets (and only when AEROL_GO_TAGS asks).
// Every other build, release builds included, gets an empty Hit that the
// compiler inlines away (failpoint_off.go), so a call site costs nothing.
//
// Protocol, under the tag: the suite writes a sandbox-name prefix to
// Dir/<name>. The first Hit(name, key) whose key starts with that prefix
// renames the file to Dir/<name>.hit (a failpoint fires once), writes the
// key into it, and blocks for the life of the process. The suite waits for
// the .hit file, which also tells it which node to kill, and SIGKILLs
// sandboxd there.
package failpoint

// Dir is where armed failpoints live on a node. /run/sandboxd is made by the
// sandboxd unit's ExecStartPre (root, 0700) on tmpfs, so only root can arm
// one and none survives a reboot.
const Dir = "/run/sandboxd/failpoints"

// HitSuffix names the marker a fired failpoint leaves next to its file.
const HitSuffix = ".hit"

// CreateBeforePersist fires in Service.createSandbox after the runtime has
// created and started the sandbox and before its row is stored: a crash here
// leaves a running container, a held network slot and a placement
// reservation that no row records (UC-480). The key is the sandbox name.
const CreateBeforePersist = "create-before-persist"
