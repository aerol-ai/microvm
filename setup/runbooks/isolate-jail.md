# Runbook: Isolate jail (workerd confinement)

Isolates share one `workerd` process per tenant group, so the process
boundary is the cross-tenant boundary (plans/isolate-runtime.md §2.1). The
jail is what makes that boundary hard. With `SB_ISOLATE_USE_JAIL=true` (the
default) every group process runs:

| Property | Mechanism | How to see it |
|---|---|---|
| Not root | shim drops to `SB_ISOLATE_JAIL_UID/GID` (`sandboxd-isolate`, created by `install.sh --with-isolate`) | `grep Uid /proc/<pid>/status` |
| Cannot regain privilege | `PR_SET_NO_NEW_PRIVS` | `grep NoNewPrivs /proc/<pid>/status` → `1` |
| Syscall allowlist | classic-BPF seccomp, installed before `execve` so the loader runs under it | `grep Seccomp /proc/<pid>/status` → `2` |
| Sees only its files | chroot into `SB_ISOLATE_JAIL_CHROOT_BASE/<group>`: `/workerd`, its shared libs, `/dev/{null,zero,random,urandom}`, `/tmp`, and a writable `/run` for its sockets | `readlink /proc/<pid>/root` |
| Bounded CPU and memory | cgroup v2 `SB_ISOLATE_JAIL_CGROUP_ROOT/aerolvm-isolate-<group>` with `cpu.max` / `memory.max` from the group's caps | `cat /proc/<pid>/cgroup` |

The daemon builds the chroot base (`<base>/.base`: workerd + libraries +
device nodes) once at start and **fails boot** if it cannot — a jail that
cannot be realized is never discovered by a tenant's create. Each group's
root is hard-linked from that base (no copies); warm-pool blanks are jailed
identically and take the claiming tenant's caps when claimed.

## Enterprise mode

`SB_ENTERPRISE_MODE=true` with `SB_ENABLE_ISOLATE=true` requires
`SB_ISOLATE_USE_JAIL=true` and `SB_ISOLATE_SECCOMP_MODE=enforce`; the daemon
refuses to boot otherwise. Jail-off and the audit / off filter modes are for
bring-up and diagnosis only.

## Bringing up a new workerd build

The syscall allowlist (`internal/runtime/isolate/jail.go`) is what a
glibc-linked V8 host is known to need. A new workerd release may call
something new; under `enforce` that kills the group at startup and creates
fail with `workerd exited during startup`.

1. Set `SB_ISOLATE_SECCOMP_MODE=audit` in `/etc/sandboxd/sandboxd.env` and
   restart. Unlisted syscalls are now **allowed and logged**.
2. Create an isolate sandbox and drive it. Read the kernel audit log:

   ```bash
   sudo journalctl -k | grep -E 'audit.*type=1326.*comm="workerd"'
   # or: sudo ausearch -m SECCOMP -c workerd
   ```

   Each line names `syscall=<nr>`; translate with `ausyscall <nr>` or the
   arch's table in `pkg/isolate/seccomp_nr_linux_*.go`.
3. Add the names to `seccompBaseAllow` (or the JIT group if V8-only), run
   `go test ./internal/runtime/isolate/` (the never-allow list must stay
   disjoint), redeploy, set the mode back to `enforce`.
4. Confirm with `make integration-single-isolate-jail` (UC-109).

`SB_ISOLATE_SECCOMP_MODE=off` installs no filter; use it only to rule the
filter in or out when a group misbehaves, never as a steady state.

## Symptoms

| Symptom | Cause | Fix |
|---|---|---|
| Daemon fails boot: `isolate jail: prepare chroot base: ... shared library ... not found` | `ldd` of workerd names a library the host lacks | Install it, or point `SB_ISOLATE_WORKERD_PATH` at a static build |
| Daemon fails boot: `this host cannot realize a jail (Linux root required)` | non-Linux host or not root | Run as root on Linux, or `SB_ISOLATE_USE_JAIL=false` (unconfined; never in enterprise) |
| Create fails: `jail required but not realized here` | per-group realization failed after boot (cgroup root not delegated, chroot base removed) | Log line names the step; check `SB_ISOLATE_JAIL_CGROUP_ROOT` is a writable cgroup v2 directory and `<base>/.base` still exists |
| Create fails: `workerd exited during startup`, `sandboxd --isolate-jail-exec` printed `chroot ... operation not permitted` | daemon not root | Run as root |
| Create fails: `workerd exited during startup`, kernel log shows `type=1326 ... comm="workerd"` | allowlist gap | Audit mode procedure above |
| Group works but `/proc/<pid>/status` shows `Seccomp: 0` | `SB_ISOLATE_SECCOMP_MODE=off` left behind | Set `enforce`; enterprise boot refuses `off` |

## What the jail does not do

- No PID or network namespace: the process sees the host's PIDs (not
  `/proc`, which is not mounted in the chroot) and reaches the network only
  through the host-side egress proxy over its unix sockets.
- Group-level caps only: one hot-looping sandbox can starve its own tenant's
  siblings (OSS workerd has no per-isolate CPU enforcement). `per-sandbox`
  granularity (`SB_ISOLATE_GROUP_GRANULARITY`) trades density for a group
  per sandbox.
- A JIT profile must allow W^X page flips. `SB_ISOLATE_JITLESS=true` removes
  them (mprotect/mmap with `PROT_EXEC` on anonymous memory are refused by
  argument rule) at a large throughput cost.
