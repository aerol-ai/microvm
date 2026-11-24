# Closing the four security gaps (M1–M4)

Status: **draft for review**, 2026-11-19. Code base: `main` at `eb1149db`.

Where the gaps come from: the capability matrix of 18 November 2026
(AerolVM `main 5c656e2e` against AWS Nitro Sandboxes and agent-sandbox
v1.0.11). It found four security rows where AerolVM trails both rivals.
This plan says, for each one, whether we can close it, how, what it costs,
and in what order. It builds on `plans/kubernetes-v2-architecture.md` (§8.7,
§18 items N2 and N7, §20) and the "pod mode" entry in `TODOS.md`.

## How to read this plan

- Section 1 is the short answer. Read it first.
- Section 2 lists the facts we checked, with sources. AWS Nitro Sandboxes
  launched on 9 November 2026, so every AWS claim here comes from its docs,
  not from memory.
- Sections 3 to 6 are the four items, one each.
- Section 7 is the order of work. Section 8 maps the repo's hard rules
  (CLAUDE.md) onto this work. Sections 9 and 10 are risks and the decisions
  we need from the owner.

Words used here:

- **Agent**: `sandboxd` in the worker role. It parses API calls.
- **Root helper**: the new small root process that M1 adds.
- **Nitro VM**: a Firecracker VM made through `/dev/nitro_enclaves` instead
  of `/dev/kvm`.
- **Direct mode / confidential mode**: the two Nitro VM modes. In direct
  mode the host can read the VM's memory. In confidential mode it cannot.

---

## 1. The answer in short

| Gap | Can we close it? | How | Size | Needs | The row after |
|---|---|---|---|---|---|
| **M1** Code that reads tenant input runs as root | **Yes.** It is all our own code. | Split `sandboxd`. The agent runs as a normal user with no rights. A small root helper does only checked work. containerd is reached only through a gate that checks every write. | L (about 12 PRs) | Nothing | Trails → **Even** |
| **M2** No hardware wall on ordinary EKS machines | **Yes, two ways.** | (a) Our KVM Firecracker on Intel 7th/8th-gen nodes with nested virtualization. It keeps snapshots, pause, moves and the warm pool. (b) Our Firecracker through the Nitro Enclaves driver. It works on any 5th-gen or newer Intel, AMD or Graviton instance, but has no snapshots. | (a) M, (b) M–L | Two cheap spikes first (§4.2) | Trails → **Even**. With (a)'s snapshots and our egress control, **Leads**. |
| **M3** No confidential memory, no attestation | **Mostly.** | Run (b)'s VMs in Nitro confidential mode. Release a sandbox's secrets only to a guest that proves what it runs. v1 refuses host exec and file access, as EKS does. v2 adds an end-to-end channel from our SDKs to the guest, so exec and files keep working. | v1 L, v2 L | M2 (b) | Trails → **Even** (v1), **Leads** (v2) |
| **M4** Privileged pods in your cluster | **Yes, as a second install mode.** | "Pod mode": each sandbox is its own pod with a RuntimeClass (gVisor, Kata or Nitro). The AerolVM worker runs unprivileged. It costs the speed and density of the default install. | M–L | Nothing (design now; build on a buyer trigger or after M1) | Trails → **Even** in pod mode |

What we cannot close, said plainly:

- **The default install keeps one privileged container.** After M1, the
  `runtime` container is still privileged. It holds containerd, the root
  helper and the sandboxes, but no code that parses tenant input. Only pod
  mode (M4) has no privileged pod at all.
- **M3 is AWS only.** It rests on the Nitro System. AKS would need a
  different stack (AMD SEV-SNP confidential VMs). That is not in this plan.
- **Nitro VMs cannot snapshot, pause or move with memory.** That is an AWS
  limit. Snapshots stay on KVM Firecracker (M2 a) and gVisor.

**Every new option is an add-on** (owner requirement, 2026-11-20). Nothing
replaces today's paths; each new strategy is chosen by a setting:

| Option | How you pick it | Default | Today's path |
|---|---|---|---|
| KVM Firecracker (today) | `runtime: "firecracker"` | as now | unchanged: v1.15.1, template snapshots, snapshot warm pool, pause, moves |
| KVM Firecracker on EKS nested-virtualization nodes (M2 a) | the same runtime; a node-pool setting | off until such a pool exists | same driver and features |
| Firecracker through Nitro (M2 b) | `runtime: "firecracker-nitro"`; Nitro node pools set `SB_FIRECRACKER_BACKEND=nitro`; optional parked warm pool per node pool and image (D21) | off | untouched |
| Confidential (M3) | `confidential: true` on a Nitro create | off | untouched |
| Pod mode (M4) | chart `install.mode: pod` | off | untouched |
| Root split (M1) | `privilegeMode: split \| single` | `split` for new installs; existing installs keep their mode until switched (D22) | `single` is today's mode, kept and tested |

Order: start M1 and both M2 spikes now. Build M2 next. M3 comes after M2 (b).
Write up the M4 design now and build it on a buyer trigger (section 7).

---

## 2. What we checked

### 2.1 AWS Nitro Sandboxes on EC2

Sources: the EC2 guide pages "Nitro Sandboxes", "Running Firecracker",
"Attestation" and "NUMA", and Firecracker's own docs
(`docs/nitro-sandboxes/*.md`, `CHANGELOG.md`) on GitHub. Links are in Sources.

| Fact | What it means for us |
|---|---|
| Upstream, open-source Firecracker **v1.18.0** added it ("Added support for Nitro Sandboxes"). Licence: Apache-2.0. | Same binary for KVM and Nitro. We pin **v1.15.1** today (`packaging/images/versions.env:35`). |
| Turned on by `PUT /enclave` (or an `enclave` key in the config file) before `InstanceStart`. Fields: `direct_mode`, `debug_mode`, `cpu_overcommit`, `hotplug_mode`, `cpu_ids`, `numa_nodes`. | One new API call in our client (`pkg/firecracker/client.go`), not a new driver. |
| "Sandboxes run under the jailer like any other microVM, with no extra flag." The jailer makes `/dev/nitro_enclaves` inside the chroot. | Our jailer argv (`internal/runtime/firecracker/jailer.go:jailerArgv`) should work. The spike must confirm it. |
| The instance must be **launched** with Nitro Enclaves on (`--enclave-options Enabled=true`). | A node-pool setting. It cannot be switched on later. |
| A memory pool is reserved **at boot**: kernel argument `nitro_enclaves.mempool=<size>@<node>`, then a reboot. "Without a pool, you can't launch Nitro Sandboxes." | Needs a custom node image or a first-boot reboot. The spike picks one. |
| Amazon Linux 2023 kernel `6.18.51-120.162` or later. | Our EKS AL2023 nodes ran 6.18.56 in Phase 0. |
| Supported: M5–M9, C5–C9, R5–R9 and more. Intel, AMD and Graviton. **No metal.** Nested virtualization **cannot** be on at the same time. | M2 (a) and (b) need **separate node pools**. |
| At most **5 VMs per vCPU** and **896 per instance**. At least **256 MiB** each, in 2 MiB steps. Each VM costs 2 MiB of pool plus a PCIe slot. | A new admission rule. Our driver has no VM-count cap today. |
| On two-threads-per-core instances, "a core runs one sandbox or the parent at a time". Use an even vCPU count. | Whole cores per VM: 2 vCPU minimum on Intel and AMD. Good against side channels, bad for density. |
| A `cpu.max` limit on the Firecracker process "does not throttle the guest". | CPU is given in whole vCPUs, not shares. |
| **Rejected:** snapshot and restore, pause and resume, dirty-page tracking, balloon, huge pages, `smt`, CPU templates, memory hot-plug, pmem. Entropy (virtio-rng) is rejected in confidential mode. | Our Stop, Start, Pause, Resume and moves all use snapshots today (see 2.4). |
| **Supported:** block, net (TAP), vsock, initrd, MMDS, the jailer. PCIe only, no MMIO. | Our toolboxd channel (vsock port 1024) and TAP networking carry over. |
| The guest kernel must be an **EFI-stub `bzImage`** on x86_64. "The `vmlinux` images used for KVM microVMs cannot boot a sandbox." Confidential mode needs the DMB virtio patches. Attestation needs `CONFIG_NSM=y`. | A second guest kernel build. Firecracker ships the DMB patches in `resources/patches/dmb/`. |
| **Confidential mode is the default.** "Neither the parent instance nor its administrators can read or change that memory." The parent still "carries the device traffic, chooses the image, and controls when the Nitro Sandbox runs". EBS and SSE-KMS "do not protect data from the parent instance". | Memory is safe. Disk, network and timing are not. The guest must encrypt its own disk and use TLS end to end. |
| **Direct mode:** the parent can read and write VM memory. "There is no NSM and no attestation." It is "equivalent to that of a nested virtual machine". | Direct mode is the M2 wall. Confidential mode is M3. |
| **Attestation:** in the guest, `/dev/nsm` makes a document signed by the Nitro PKI (root: AWS Nitro Enclaves Root-G1). SHA-384 PCRs: PCR0 = kernel, command line and initrds; PCR3 = parent's IAM role; PCR4 = parent instance ID; PCR16–31 = set by the workload. | We can measure the image and the sandbox's policy into PCR16–31 ourselves. |
| **KMS:** `Decrypt`, `GenerateDataKey` and others accept the document. Key policies use `kms:RecipientAttestation:PCR<N>` and `kms:RecipientAttestation:ImageSha384`. The answer comes back encrypted to the guest's key (`CiphertextForRecipient`). AWS warns: "PCR3 and PCR4 identify only the parent instance"; in debug mode the other PCRs read zero. | Secrets can be released only to a measured guest. A policy must always pin PCR0. |
| No extra charge. | Only the EC2 instance. |

### 2.2 AWS Nitro Sandboxes on EKS

Source: the EKS guide's sandboxing pages and the AWS warm-pool sample.

- Two RuntimeClasses, `isolated-sandbox` and `confidential-sandbox`. EKS
  1.36 or later. Auto Mode needs no setup. Node groups need a custom AMI and
  `EnclaveOptions.Enabled=true`.
- AWS: "designed to run untrusted container images". "It is not designed to
  run untrusted pod specs." "Treat pod spec submission as a privileged
  operation."
- Confidential mode on EKS refuses exec, stdin and process listing. The
  writable layer and `emptyDir` are encrypted. **Still visible to the host:**
  Pod Identity ("the parent instance can mint Pod Identity credentials for
  any pod scheduled on the node"), CSI secrets, EBS and EFS.
- The sample's start times: a sandboxed pod cold-starts in 3.2–3.7 s; a warm
  claim through agent-sandbox's `SandboxWarmPool` takes 0.8 s.
- Per-sandbox defaults: 100 Mbps, 1,500 packets/s, 100 DNS queries/s,
  4,096 conntrack entries in the node's shared table.

### 2.3 EC2 instance attestation (NitroTPM)

Source: the EC2 guide's NitroTPM attestation pages.

- A whole EC2 instance can prove what it booted, if it was built as an
  **attestable AMI**: Amazon Linux 2023 (or NixOS) built with KIWI NG, UEFI
  boot, NitroTPM on. PCR4, PCR7 and PCR12 identify the AMI.
- The document chains to the same AWS Nitro root. A verifier can check it
  without KMS. KMS keys: `kms:RecipientAttestation:NitroTPMPCR4/7/12`.
- The pages say nothing about the EKS-optimized AMI or Bottlerocket. We
  would have to build our own attestable worker AMI.

### 2.4 Our own code

- **What runs as root:** the full list is in section 3.1.
- **Firecracker today** (`internal/runtime/firecracker/`):
  - A create with no template already cold-boots with no snapshot
    (`driver.go:Create` → `configureVMM`). It took 1.6 s end to end on kind
    with nested virtualization (Phase 5 results).
  - **Stop, Pause, Start and Resume always use snapshots**
    (`driver.go:Stop` → `stopToSandboxSnapshot`; `Start` →
    `startFromSandboxSnapshot`). There is no cold restart path.
  - Template snapshots are on by default (`SB_FIRECRACKER_SNAPSHOT_ENABLED`).
    The warm pool is off (`SB_FIRECRACKER_VMM_POOL_ENABLED`).
  - `configureVMM` sets `TrackDirtyPages: true` on every boot. Nitro rejects
    dirty-page tracking.
  - `RuntimeHealth` requires `CONFIG_VMGENID=y` in the guest kernel
    (`driver.go:validateVMGenIDCapability`). That only matters for snapshot
    clones.
  - There is no backend setting. `Service.firecracker` is one field
    (`internal/service/service.go:120`). The client seams in `seams.go` use
    Firecracker's own types, which Nitro mode keeps.
- **Spike S6 passed:** Firecracker v1.18.0 boots on an m8i.xlarge with
  nested virtualization (820–860 ms per bare cold boot). Firecracker in the
  worker pod passed on kind on the same kind of machine (`fckind.sh`,
  runs `p5-fc-1` to `-4`). It has never run on EKS.
- **S7 and S9:** a list of 14 capabilities works only for a one-container
  worker, because two-way mount propagation needs a privileged container.
  A user-namespaced pod (`hostUsers: false`) loses per-sandbox cgroup limits
  (`charts/aerolvm/EVIDENCE.md`).
- **Open findings this plan also fixes:** F8 (network namespaces leak into
  the machine's mount table), the F13 follow-up (mount helpers need one
  process namespace for the whole pod) and C14 (host processes need one
  process namespace too). All three exist because the agent and the runtime
  container share mounts and processes. M1 removes that sharing.

---

## 3. M1: split `sandboxd` so tenant-facing code has no rights

### 3.1 What `sandboxd` does as root today

Grouped by kind. "Moves to" is where it goes in this plan.

| Work | Where today | Moves to |
|---|---|---|
| Make a network namespace, bind it under `/run/netns`, loopback up, IPv6 off | `internal/network/netns/host_linux.go` (`createNamedNetns`, `loopbackUpIn`), `hostnet/ipv6_linux.go` | Root helper: `Realize(slot)` (the `HostManager` interface) |
| CNI add and delete (veth, bridge `aerolvm0`, addresses, routes, masquerade) | `internal/network/cni/cni.go` (`ExecRunner.Add/Del`) | Root helper, same call |
| Read a sandbox's IP by entering its namespace | `internal/runtime/containerd/network_ip_linux.go` | Root helper returns it from `Realize(slot)` / `IPv4Addrs(slot)` |
| Boot sysctls, `br_netfilter`, base nft tables (F1, F2) | `hostnet/sysctl_linux.go:ensureForwardingSysctls`, `netrules` | Root helper, once at start |
| Per-sandbox egress, ingress, block-all and hold rules | `pkg/docker/netrules/netlink_backend.go`, `internal/runtime/containerd/network_rules.go` | Root helper. **Typed** policy in, never rule text. |
| Node guard, egress floor, IPv6 fence, host-port DNAT, conntrack flushes | `netrules/nodeguard.go`, `floor.go`, `internal/network/ipv6fence`, `internal/network/hostport` | Root helper, with its own periodic re-assert |
| F10 out-of-memory settings per sandbox | `containerd/cgroup_parent.go:markWholeOOMVictim` | Root helper |
| Host-process cgroups (WASM, V8, Firecracker), isolate group caps, VMM freeze/kill | `pkg/hostproc`, `pkg/isolate/cgroup.go`, `firecracker/vmm_process_linux.go` | Root helper |
| Read-only mount of each image's snapshot to read `/etc/passwd` and `/etc/group` (inside containerd's client library) | `containerd/lifecycle.go:Create` → `oci.WithImageConfig` | Root helper: `ResolveImageUser`, cached per image digest |
| XFS project quota on a sandbox's writable layer | `containerd/disk_quota_linux.go` | Root helper, path must be under the snapshot root |
| External mounts: `mount -t nfs`, `sshfs`, `rclone`, `mount-s3` run as root with tenant-shaped options | `pkg/mounts/manager.go`, `process.go`, `adapters/*.go` | Root helper. FUSE tools run as a normal user. |
| Platform volume reclaim (temporary NFS mount, `rm -rf`) | `pkg/volumes/reclaim.go` | Root helper |
| V8 jail: tmpfs, `mknod`, hard links, `chown` | `pkg/isolate/chroot_linux.go`, `host_jail_linux.go` | Root helper |
| Firecracker: jailer start, rootfs hard link and `chown`, `mkfs.ext4` overlay, TAP devices, TAP NAT | `firecracker/jailer.go`, `driver.go:chrootFilePath`, `internal/network/tap/*` | Root helper |
| gVisor checkpoint and restore for moves | `containerd/gvisor_move.go` | Root helper |
| WASM workers and resident hosts: re-exec of `sandboxd` **as root**, with only an env allowlist and a cgroup | `pkg/wasm/worker/supervisor.go:DefaultSpawner` | Root helper spawns them as a normal user with seccomp (and quick win Q1 does this first) |
| **The containerd socket.** Anyone who can write to it can start a privileged container. | `containerd/client.go:Connect` | **The containerd gate** (3.3) |
| Node upgrade (replace binaries, `systemctl`) on VMs | `internal/nodeupgrade/host.go` | Root helper, only after it checks the new binary's signature |

Tenant input that the same root process handles today:

| Input | Where | Risk today |
|---|---|---|
| HTTP API, Daytona, E2B, Runloop facades, MCP | `pkg/api/...`, `pkg/api/remotemcp` | Parsed as root |
| Multipart uploads (Daytona over 64 MiB, Runloop over 32 MiB) | `pkg/api/daytona/toolbox.go:238`, `pkg/api/runloop/files.go:210` | Written to root-owned temp files |
| WASM modules | `internal/service/wasm_module_api.go` | Compiled and run by **root** worker processes. An engine escape is root. |
| WASM file and exec calls | `internal/runtime/wasm/toolhost/path.go:openInWorkDir` | Host filesystem as root, held in only by `os.Root` |
| Image build context tars | `containerd/buildkit.go:extractTar` | Unpacked as root into the host temp folder |
| Image refs | `containerd/lifecycle.go` | Every image's snapshot is mounted inside `sandboxd` |
| Mount specs | `pkg/models/mounts.go:Validate` | NFS `opts` and S3/rclone `extra_args` reach root-run tools. Only credential-shaped words and a leading dash are refused. Operators only, today. |
| Move bundles from other workers | `service/snapshot_move.go`, `gvisor_move.go`, `firecracker/sandbox_move.go` | Written as root, fed to `runsc restore` |

### 3.2 Three ways to split, and the one we pick

| Option | What the root part holds | Verdict |
|---|---|---|
| **A. Checker split (pick this)** | A small root helper that does typed, checked operations (network, firewall, cgroups, mounts, host processes), plus a **containerd gate** that passes reads and checks every write against fixed rules. All business and driver logic stays in the agent. | The root part is small and stable. The agent can be upgraded every release. |
| B. Move the runtime drivers into the root part | Everything behind the `runtime.Runtime` interface (`internal/runtime/runtime.go`) | Simple code move. But the root part becomes big, changes every release, and still parses most tenant spec fields as root. On Kubernetes it would sit in the `runtime` container, and changing that container's image restarts it and **kills every sandbox** (§8.6 of the Kubernetes plan). |
| C. A helper for network, firewall, cgroups and mounts only; the agent keeps the containerd socket | The listed work | **Gains nothing.** The containerd socket is as good as root: whoever holds it can start a privileged container that mounts `/`. |

The capability matrix and N2 describe "a small helper does only the network,
firewall, cgroup and mount work". That is option C. The inventory shows it is
not enough on its own: the gate around containerd is the part that makes the
split real.

### 3.3 The design

```
                 tenant input (HTTP, uploads, mount specs, WASM, tars)
                                   │
              ┌────────────────────▼────────────────────┐
              │ agent: sandboxd, uid 65532, no rights    │
              │ API, facades, auth, store, Raft, service │
              │ logic, driver logic, toolbox proxy       │
              └──────────────────┬───────────────────────┘
                                 │ /run/aerolvm/root.sock, one gRPC server,
                                 │ one peer uid check: the helper's typed
                                 │ calls AND containerd's own API (gated)
              ┌──────────────────▼───────────────────────┐
              │ root helper (in aerolvm-supervisor)       │
              │  • netns, CNI, firewall, cgroups, mounts, │
              │    host processes, jailer, TAP            │
              │  • containerd gate: reads pass,           │
              │    writes checked against fixed rules     │
              └──────────────────────┬───────────────────┘
                                     │ real socket, root only
                               containerd → shims → sandboxes
```

**Where the root helper runs.**

- **Kubernetes:** in the `runtime` container, as a child process of
  `aerolvm-supervisor` (`cmd/aerolvm-supervisor`, `internal/supervisor`),
  which is already PID 1 there and already root. The supervisor stays tiny
  and fixed in the runtime image; the helper is its own binary, upgraded
  with each release (eng review D4, see "Upgrades"). Network namespaces are now made in the `runtime` container where
  `runsc` uses them, so the two-way `/run/netns` mount goes away (fixes F8).
  Mount helpers and host processes start from the supervisor, so the pod no
  longer needs one shared process namespace (fixes the F13 follow-up and
  C14). That also lets the chart turn external storage on by default,
  because the `edge` container can no longer read other processes' command
  lines.
- **VMs:** the same binary runs as its own unit, `aerolvm-rootd.service`
  (root). `sandboxd.service` gets `User=sandboxd`, an empty
  `CapabilityBoundingSet`, `NoNewPrivileges=yes`, `ProtectSystem=strict`,
  `ProtectHome=yes`, `PrivateTmp=yes` and write access only to its own data
  folders. Today it has none of these (`packaging/sandboxd.service` and the
  units `scripts/install.sh` writes at lines 2829 and 4020).

**The agent container on Kubernetes** becomes: `runAsUser: 65532`,
`runAsNonRoot`, `capabilities: drop [ALL]`, `allowPrivilegeEscalation:
false`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`. It no
longer mounts containerd's root folder or `/run/netns`. That is the
`restricted` Pod Security shape, inside a namespace that still allows the
privileged `runtime` container next to it.

**The socket.** One Unix socket, `/run/aerolvm/root.sock`, `0660`, owned by
`root:aerolvm`, served by one gRPC server. It carries both the helper's own
calls and the gated containerd API: the containerd Go client in the agent
connects to it as if it were containerd. On every connection the helper reads
`SO_PEERCRED` and refuses any caller whose uid is not the agent's. On VMs it
also checks the caller's cgroup. This is the pattern the egress gateway
already uses (`internal/egress/peercred_linux.go`). One listener means one
peer check, so the two paths cannot drift apart (eng review D3). Calls are
versioned protobuf over gRPC.

**The helper's calls.** Each one is idempotent: "make sure this exists" and
"make sure this is gone". Each checks its own inputs and never trusts the
agent's checks.

| Group | Calls | What the helper checks itself |
|---|---|---|
| Boot | `EnsureHost()` | Sysctls, `br_netfilter`, base nft tables (F1), node guard, floor, IPv6 fence. Re-asserted on the helper's own timer. |
| Network | `Realize(slot)` → `{netnsPath, ip}`; `Remove(slot)`; `DisableIPv6(slot)`; `IPv4Addrs(slot)` | This is the existing `HostManager` interface (`internal/network/netns/host.go:20`). The netns pool's bookkeeping (reserve, claim, release, in the store) stays in the agent; only realization moves. The helper derives the namespace name from the slot's validated ID (sandbox or slot ID format) and builds the path under `/run/netns` itself. It never takes a path from the agent, although `Slot.netnsName` (`pool.go:138`) reads one today. |
| Firewall | `ApplyEgressPolicy(id, ip, policy)`, `BlockAll(id)`, `Hold(id)`, `Clear(id)`, `EnsureHostPort(port, target)` | The policy is typed (CIDRs, ports, gateway on or off). The helper renders the rules. It only touches that sandbox's own chain and sets. The IP must be the one the helper reads from that slot's namespace. |
| cgroups | `MarkOOMVictim(id)`, `EnsureHostGroup(kind, id, limits)`, `Freeze(id)`, `Thaw(id)`, `KillGroup(id)` | Paths are built by the helper under the fixed sandbox parent. No path comes from the agent. |
| Images | `ResolveImageUser(snapshotKey, user)` → `{uid, gid, gids}` | The key must exist in AerolVM's containerd namespace. Mounted read-only, `nosuid,nodev,noexec`, in a private mount namespace. Cached per image digest. |
| Disk | `SetDiskQuota(snapshotKey, bytes)` | The path must be under the snapshot root. |
| Mounts | `MountExternal(id, spec, sealedCreds)`, `Unmount(id, target)`, `CheckVisible(id, target)`, `Sweep()` | Re-runs `models.Mount.Validate` plus **allowlists** for NFS `opts` and each tool's `extra_args`. FUSE tools (`sshfs`, `rclone`, `mount-s3`) run as a normal user with only `/dev/fuse`. NFS gets fixed `nosuid,nodev` options. Targets are under the mounts folder only. |
| Host processes | `SpawnHost(kind, id, params)` for WASM worker, WASM resident host, workerd jail, Firecracker jailer; `PrepareJail(id)` | The binary comes from a fixed list in the helper, never a path from the agent. WASM hosts run as a normal user with no-new-privs and seccomp. Firecracker's API socket and vsock socket are handed to the agent's group. |
| Moves | `Checkpoint(id)`, `Restore(id, bundle)` | Bundles only from the moves folder. Size limits. |
| VM only | `RestartEgressGateway()`, `ApplyUpgrade(artifact)` | `ApplyUpgrade` checks the cosign signature against a key built into the helper. Otherwise a broken agent could replace a root binary. |

**The containerd gate.** containerd's API is large, so the gate is an
allowlist (eng review D6).

- **Only the methods the agent calls today pass.** PR 3 derives the list
  from `internal/runtime/containerd`. Every other method is refused,
  including containerd 2's sandbox API and namespace create, update and
  delete. Reads in the list pass through. Image pulls through the transfer
  service pass; unpacking stays inside containerd, the same as for
  agent-sandbox, where the node's containerd pulls as root.
- **Checked on allowed writes:** `Containers.Create` and `Update` (the OCI
  spec and the runtime options), `Tasks.Create` (runtime options,
  checkpoint and restore paths, rootfs mounts), `Tasks.Checkpoint` (image
  path), `Tasks.Exec` (the process spec) and `Diff.Apply` (its target
  mounts, which containerd writes into as root). The rules are the
  containerd engine's envelope (`internal/runtime/containerd/security.go`),
  written once, plus the fields below:
  - no host namespaces, except the network namespace at `/run/netns/<id>`;
  - no OCI hooks (hooks run as root on the host);
  - bind mounts only from AerolVM's own folders, never `/`, `/proc`,
    `/sys` or the sockets folder;
  - no devices;
  - capabilities only from the trimmed set;
  - seccomp present, `NoNewPrivileges` on, masked and read-only paths present;
  - the cgroup path under the sandbox parent;
  - the runtime is `runsc` or `runc`. Every runtime option is checked:
    `BinaryName`, `CriuPath`, `Root` and `ShimCgroup` name only known
    binaries and folders (a `BinaryName` of `/bin/sh` would be root code
    execution), and the runsc shim's `ConfigPath` must be the helper's own
    file (a runsc TOML can turn on host networking);
  - rootfs and `Diff.Apply` mounts: only the snapshotter's mount types, and
    sources only under the snapshotter's root. The destination alone is not
    enough: Kata's CVE-2026-77176 came from checking only the destination;
  - checkpoint and restore image paths only under the moves folder;
  - gVisor annotations only from an allowlist. For example,
    `dev.gvisor.flag.network=host` would take the sandbox out of its network
    namespace.
  - A privileged spec passes only when the helper's **own** config has
    `SB_CONTAINER_PRIVILEGED` on. It is off by default and refused in
    enterprise mode, as today.
- The rules live in one new package, `internal/rootpolicy`. The agent's spec
  builder and the gate's checker both import it, so they cannot drift. A test
  builds every spec shape the agent makes and checks the gate accepts it.
  Another mutates each field and checks the gate refuses it.
- Namespaces: only AerolVM's containerd namespace, and no default labels.
- **What building the gate taught us (T1, 2026-11-20).**
  - **Root-read paths live in root's folders.** Host files the spec binds
    in (hosts, resolv.conf), ready sockets, stdio FIFOs, the moves folder
    and the runsc config files are opened later by runc, runsc or the
    shim, as root. If they sat in a folder the agent can write, a broken
    agent could swap one for a symlink between the check and the open;
    a swapped runsc config names the binary runsc runs as root. So the
    helper creates these files in folders only root can write, and the
    agent only reads or opens them (FIFOs: helper-made, mode 0660 to the
    agent's group). This is part of T2.
  - **Pulls run in the agent.** containerd's Go client pulls by writing
    content, preparing and committing snapshots and calling Diff.Apply,
    not through the transfer service; the gate checks those writes.
  - **Exec and Checkpoint are refused at the gate.** Exec goes through
    toolboxd inside the sandbox; gVisor checkpoint runs `runsc` directly
    and becomes the helper's `Checkpoint` call.
  - **Seccomp is compared exactly** with containerd's default profile.
    The helper ships with each release (D4), so its containerd library
    matches the agent's.
  - The allowlist is 41 methods (listed in the gate's code with a reason
    each); Diff.Diff, Tasks.Update device rules, the restart monitor's
    log URI and stdio URIs are checked too.
- **Containerd upgrades.** A test pins the fields of each allowed request
  message, so a containerd bump that adds one fails the build until the gate
  decides about it. At run time, an unknown non-empty field is refused.

**Upgrades.**

- The agent is upgraded in place, every release, as today.
- **The helper is hot-swapped, signed** (eng review D4). The code it takes
  over changes often (in 30 days: `pkg/docker/netrules` 15 commits,
  `internal/network/netns` 9, `pkg/mounts` 10), and a `runtime` image change
  restarts the container and loses its sandboxes. So the helper is not baked
  into the runtime image. Each release's agent image carries the helper
  binary and its signature; the agent stages both in a shared folder; the
  supervisor runs the new helper only if the signature checks against a
  release public key built into the runtime image, and only if its version
  is not older than the one running. A helper restart never stops a
  sandbox. The agent can write the folder but cannot make root run anything
  unsigned or older.
  The supervisor never runs the staged file in place: it copies the binary
  into a root-only folder, checks the signature of that copy, and runs
  exactly those bytes, so the agent cannot swap the file between the check
  and the run (outside review O3).
  A swap is an exclusive handover, never an overlap: the old helper stops
  accepting and finishes every call in flight, and only then does the new
  helper start accepting on the same listening socket (the supervisor
  passes the file descriptor). Two helpers never mutate at once, so a late
  `Remove` from the old one cannot undo a `Realize` from the new one and
  per-sandbox order (D11) holds across the swap (outside review O6). The
  agent retries a call whose connection dropped; every call is idempotent.
- Only the supervisor itself (and containerd and gVisor) ride the runtime
  image, and changing that still needs a decommission (§10.5 of the
  Kubernetes plan). On VMs, `aerolvm-rootd.service` runs the same signed
  helper, and the node upgrade path checks the same signature.
- The API is versioned. Agent N must work with helper N−1. A feature that
  needs a newer helper is refused with a clear reason. A CI job runs the new
  agent against the last released runtime image.
- On first start, the helper moves ownership of the agent's data folders
  (database, spill folders, temp folders) from root to the agent's user, once.
- **Rolling out M1 itself** (eng review D5). M1 changes the worker pod's
  settings, which Kubernetes applies only to new pods, and the operator
  never restamps running pods. So: the agent checks for the helper socket at
  start. Found: split mode. Not found: today's in-process root mode, which
  works only because an old pod is still privileged, so an in-place agent
  upgrade onto an old pod keeps working.
- **The split is a lasting setting** (eng review D22, which extends D5):
  `privilegeMode: split | single` (chart value and an `SB_` setting). New
  installs default to `split`. Existing installs keep their current mode
  on upgrade until the operator switches; switching rolls workers to the
  new pod template node by node through decommission. `single` is today's
  one-process root mode. Both modes stay tested for good, including a mixed
  fleet.

**Failure rules.**

- The helper is not the parent of any sandbox. Shims, VMs and hosts live
  in their own cgroups. A helper crash never stops a sandbox. The supervisor
  restarts it.
- The helper keeps no state of its own. It reads it back from the kernel
  (namespaces, cgroups, nft) and from containerd. Every call can be retried.
- The agent reaches the helper through the repo's lazy-bootstrap pattern:
  an `atomic.Bool` latch plus a `sync.Mutex` single flight, like
  `Service.EnsureLayer4Ready`. A down helper fails a create with a clear
  `503`, not a hang.
- **A refusal is a security event** (eng review D9). The agent only sends
  what its own builder made, so a refusal by the gate or the helper means
  drift or a compromise. Each one writes an audit event (call, reason,
  node) to the hash-chained log, counts in
  `aerolvm_rootd_refusals_total{call,reason}`, and a new rule in
  `setup/prometheus/sandboxd-alerts.yml` fires on any refusal within 5
  minutes, tested in `setup/prometheus/alerts_test.go`. The create fails
  with a `500`.

**What stays out.**

- The Docker engine (local mode): `docker.sock` is as good as root, and
  Docker has no gate. Local mode keeps today's model, and the docs say so.
- containerd, `runsc`, the jailer and the helper are still root. A bug in
  containerd's image unpacking is still a root bug, as it is for both rivals.
- Escapes from a sandbox are the wall's job (gVisor, Firecracker), not M1's.
- **What a broken agent still controls** (eng review R9). The agent holds
  every toolbox token on its node, the node cipher that opens their env,
  and the node's cluster certificate. So a bug in tenant-facing code can
  still reach every sandbox on that node and its secrets. M1 stops the next
  step: root on the machine, the kubelet's credentials, the instance role,
  the kernel. Per-team worker pools (N6 / matrix item S2) are what limit a
  breach to one team.

### 3.4 Quick wins to ship before the split

Each is small and stands alone. Together they shrink the root surface now.

| # | Change | Size |
|---|---|---|
| Q1 | WASM workers and resident hosts drop to a normal user, with no-new-privs and a seccomp filter. This was the riskiest finding: an engine escape is root today. **Resized (2026-11-20):** workers open files by path under two root-only folders (`/var/lib/sandboxd`, `/run/sandboxd`), so a plain uid drop either breaks them or loosens that hardening. Design approved by the owner: the worker starts as root, opens its socket, compile cache and its own spill folder, then drops uid/gid, no-new-privs, dumpable=0 and seccomp; sandboxd opens each path a message names (modules, work dirs, mount folders, snapshots) and passes the open file; each worker gets its own PID namespace; an unreadable floor file fails closed; the compile cache cannot be poisoned across tenants. S3/rclone mounts keep working through passed files. | M |
| Q2 | Allowlists for NFS `opts` and for each mount tool's `extra_args`. A refused flag gets a clear `400`. Today only credential-shaped words and a leading dash are refused. Review added (2026-11-20): rclone backends are allowlisted in the source and in `rclone_conf` (no `local`, no wrappers around it, no options that run commands or read host paths); the operator's platform-volume settings are checked once at daemon start; stored specs are re-checked on start and restart. | S–M |
| Q3 | Image build contexts unpack in a child process with no rights, into a folder it owns. (The builds themselves move to rootless BuildKit in M1 PR 10b, eng review D14.) | S |
| Q4 | Multipart parts are written to a temp folder only the API can use, cleaned up per request. | S |

### 3.5 The PRs, in order (stacked)

1. `internal/rootpolicy`: the shared rules, as pure functions, with table
   tests and Go fuzz tests.
2. The helper's socket, peer check, version call, and the agent's client
   with the latch.
3. The containerd gate.
4. Network: namespaces, CNI, IP (closes F8 on Kubernetes).
5. Firewall and host-port calls.
6. cgroups and F10.
7. `ResolveImageUser` and disk quota. The agent stops mounting containerd's
   root.
8. Mounts (closes the F13 follow-up).
9. Host processes: WASM, V8, Firecracker jailer and TAP (closes C14).
10b. Builds (eng review D14). First step done separately (PR #1371): build
    steps run on the sandboxes' CNI network behind the egress floor and node
    guard. Then: buildkitd runs rootless (BuildKit's rootless
    mode, OCI worker) with its own network that gets the sandboxes' egress
    rules. A build exports an OCI archive that the agent imports through the
    gate's allowed transfer import. The agent then holds no root-level socket
    on VM installs either. (Today buildkitd runs as root with direct
    containerd access, outside the gate.)
    **What building it taught us (T6, 2026-11-22).**
    - **The import is the client's, not the transfer service.** Like a
      pull (T1), the agent reads the archive itself and sends content
      writes, labels, an image record and an unpack, which the gate
      already checks. The transfer and streaming services stay refused:
      through them containerd would read an archive written by the
      process that ran tenant build steps, as root. The agent's reader
      takes only an OCI layout, a bounded size
      (`SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES`, 16 GiB), one image, the
      build's own tag as its name, and checks every blob's bytes against
      its name even when containerd already has that content.
    - **A setting, following the privilege mode.**
      `SB_CONTAINERD_BUILDKIT_ROOTLESS` unset is on in split (the only
      way split builds; split with it off fails boot) and off in single,
      so single keeps today's root buildkitd (D22, R18). Single can opt
      in: install.sh `--buildkit-rootless`, or `containerd.buildkit_rootless`
      in `config/cluster.yml` for Terraform.
    - **One thing rootless BuildKit cannot do:** see containerd's images.
      Every `FROM` comes from a registry, so an operator's build from an
      image only the node has (a snapshot, an earlier build) needs the root
      BuildKit. Tenant builds already refuse such images. Follow-up: hand
      such a base to BuildKit as an OCI layout context.
    - **The network is a namespace on the sandboxes' bridge.** Rootless
      buildkitd joins `aerolvm.build`, which a root oneshot unit builds with
      sandboxd's CNI config (`sandboxd host build-network up`), so pulls and
      steps leave with a sandbox address and get the floor and the node
      guard with no new host rule. Steps live behind RootlessKit
      (`--detach-netns`), not on the sandboxes' bridge, so the host's drop
      between sandbox addresses never sees step-to-step traffic. Review of
      #1398 (F4) found BuildKit's own bridge let one build's step reach
      another's: each step now gets a point-to-point link of its own (CNI
      `ptp`, so no shared segment to spoof on), and `sandboxd host
      build-network guard` runs inside RootlessKit before buildkitd and
      drops what a step sends to another step, to that namespace, to
      RootlessKit's own network or to `aerolvm.build`'s addresses, with
      strict reverse-path filtering and IPv6 off in that namespace (the
      rules are IPv4; a second review found a step reaching it over IPv6
      link-local). Proven live with the reviewer's
      two-build probe. RootlessKit is 0750 to the build user's group, so
      its AppArmor user-namespace grant is the build user's alone; split
      mode on VMs (PR 10) must give the agent the socket by other means
      than that group. Ansible sets no BuildKit up, so it is unchanged.
10. VMs: the two units, `install.sh`, Ansible, Terraform bootstrap, and the
    one-time ownership move.
    **What building it taught us (PR 10, 2026-11-23).**
    - **`install.sh --privilege-mode split|single`**, saved in node.json
      like every setting; Terraform's `privilege_mode` in
      `config/cluster.yml` passes it on the one-line join path; Ansible
      checks each node runs that mode and never switches one (a switch
      makes users, writes units, installs the helper, moves owners).
    - **The ownership move runs before every sandboxd start, not once.**
      Root tools keep writing into the agent's folders after the switch
      (`sandboxd init` and `join`, `key wrap`, the upgrader's database
      restore). `aerolvm-rootd agent-folders`, as root in the unit
      (`ExecStartPre=+`), gives the agent what root owns there: no link
      followed (one handle per entry, the owner read and changed through
      it), no mount entered (statx's mount-root mark, or a new device),
      other users' files and hard-linked files left alone. After the first
      start it only reads. The way back is the installer's, since single
      runs no helper: it first removes what the root agent would act on by
      path at boot and the agent could write (the upgrade records, the
      runtime folders, every link). The database stays, so switching back
      trusts what the agent wrote: a node thought broken into is rebuilt.
    - **The upgrader's folder moves out of the agent's.** Beside the
      database the agent could swap a staged binary between its check and
      its install (root runs `sandboxd` in install.sh). Split sets
      `SB_UPGRADE_STATE_DIR` to a folder of root's; `sandboxd upgrade
      recover` runs as root before sandboxd starts, and refuses an upgrade
      folder inside the agent's; upgrades over the API are off until the
      helper's `ApplyUpgrade` exists. Boot recovery takes no path from a
      record: the database is the node's own, a backup must be the upgrade
      folder's own, and a record naming files outside the node's layout is
      left alone. A switch of mode removes single mode's upgrade folder.
    - **The node upgrade checks the helper with the supervisor's code**
      (`internal/rootswap`): signed manifest, this release, not older,
      the checked copy installed. release.yml signs in a job of its own,
      from a `release` environment secret, skipped without it.
    - **Two sockets needed more than the group:** the egress gateway's
      control socket (its peer uid, `SB_EGRESS_PEER_UIDS`) and rootless
      BuildKit's (an ACL for the agent, never the build user's group).
10c. Split mode's last containerd gaps (PR 13): the containerd warm pool
    and gVisor checkpoint moves.
    **What building it taught us (PR 13, 2026-11-23).**
    - **The warm pool needed no new helper call.** A park is a split
      create (PR 7's one PrepareSandbox call), and the slot's park socket
      gets its name in the helper's folder from EnsureReadySocket with no
      nonce, which every helper has served since PR 7. The park socket
      stays the agent's, so the adopt frame and the env it carries never
      pass through the helper. A claim needs no root work beyond the
      gate's relabel and the firewall's rules; a disk limit goes through
      the disk_quota part, as a resize's does.
    - **Moves are five calls at the end of the service** (CheckpointMove,
      ExportMove, ImportMove, StagedMove, DropMove). The bundle's bytes
      stream through the helper, which copies them into root's own files:
      runsc reads them as root, and a file the agent still held could
      change after the helper's check. The helper reads only the move
      bundle format, bounds a bundle's bytes (a refusal) and the bundles
      staged at once (busy), and the gate takes a restore only from
      `<moves>/in/<the container's own ID>`.
    - **A gVisor move stays within one privilege mode.** The bundle format
      is the same, so each mode stages the other's bundle. But runsc
      (release 20261102.0) refuses a restore whose bind options differ
      from the checkpoint's, on by default, and the ready socket's bind is
      read-write in single and read-only in split (the gate's rule). A
      runsc box run shows the refusal both ways. So the checkpoint-moves
      label now carries the mode, and the decommission leader refuses a
      gVisor move to a target of the other mode before the source saves
      anything. While a fleet switches from single to split, a gVisor
      sandbox keeps its memory only if a node of its own mode takes it.
    - **A stream needs a cancel of its own.** The client's call bound
      hands back the caller's context unchanged when it has a deadline, so
      cutting an import whose source failed needs a cancel the client
      makes for the stream. A test found it.
    - **Live, in a privileged Docker Desktop box** (kernel 5.10, arm64):
      parks, a warm claim with env, a stop and start that sends the env
      again, deletes, the boot purge and the drain all ran as uid 65531
      through the helper. A gVisor sandbox moved through the helper with
      real runsc (systrap): checkpoint 229 ms, a 2.5 MB bundle, restore
      426 ms, and a file in its memory-backed root survived.
    - **A warm claim's cost is its trips, so a split claim reads once.**
      Timed call by call in the box (8 paired rounds, 100 runs each), a
      trip through the gate costs about 0.4 ms and the firewall's lift
      through the helper about 0.4 ms. With single mode's three reads of
      containerd the split claim came out over the +1 ms budget; with one
      list in their place it adds +0.72 ms p50 (bootstrap 95% CI +0.44 to
      +0.89). End to end, on the idle box (10 paired rounds, 160 pool
      hits), the pool stage adds +1.25 ms (CI +0.25 to +2.75) and the
      whole create +0.51 ms (CI -1.14 to +2.09): both hold +0.72 ms, and
      neither is tight enough to prove the budget. The EKS drill takes the
      N1 numbers.
    - **The helper takes moves from its own settings.** It serves the move
      calls only with `SB_GVISOR_CHECKPOINT_MOVES` on in its own
      environment, so the chart (PR 11, which merged first) passes that
      setting to the runtime container too, and drops its split refusals
      of the warm pool, of gVisor moves and of the agent-sandbox API's
      warm pools. Moves stay off by default in split, as before.
    - **A checkpoint belongs on the sandboxes' disk.** It is about a
      sandbox's memory in size. In the chart the helper's moves folder is a
      folder of containerd's volume, so a move cannot fill the runtime
      container's own disk, and the agent's disk floor counts it. The
      helper trusts a folder only when no one else can write it, and the
      chart cannot know how the kubelet makes it (an emptyDir is open to
      everyone), so the split-folders init container makes it root's, mode
      0700, before the helper checks it.
11. Chart: the agent container as described in 3.3; drop the two-way mounts
    and `shareProcessNamespace`; turn external storage on by default.
    The operator rolls workers to the new template node by node through
    decommission; the dual-mode agent (D5) covers pods still on the old one.
    **What building it taught us (PR 11, 2026-11-23).**
    - **The chart value is `privilegeMode: single | split | auto`, and the
      default stays `single`** until the EKS drill (D10). `single` renders
      byte for byte what the chart rendered before. `auto` is the later
      default: a new install gets `split` unless a value needs `single`;
      an upgrade keeps the mode the release's worker template has now
      (Helm `lookup` of the single-mode StatefulSet or cluster mode's
      pod-templates ConfigMap; a template with no `SB_PRIVILEGE_MODE` is
      `single`, and an upgrade that cannot read it keeps `single`). The
      flip is then one line in `values.yaml` (`single` to `auto`).
      `helm template` cannot read the cluster and renders `auto` as a new
      install, so GitOps users set the mode itself; the docs say so.
    - **The agent's uid is 65531, not 65532.** The helper refuses 65532 by
      number (review H3): edge, egress and the operator share it, and the
      peer check goes by uid. 65531 is the helper's default.
    - **The fallback is the setting, not the socket.** The agent does not
      look for the helper's socket (D5's first idea); it reads
      `SB_PRIVILEGE_MODE`, absent meaning `single`. A pod made from an
      older template has no such setting, so an in-place agent upgrade
      onto it runs `single`, which is what D5 needs.
    - **Nothing staged the helper.** `rootswap.Stage` had no caller and the
      agent image carried no helper. The agent image now ships
      `aerolvm-rootd` with its signed manifest and signature (the release's
      images job waits for `sign-rootd`), and the agent's start command
      copies the three files to the staging folder before `sandboxd`
      starts. Re-staging the same release swaps nothing (the keeper skips
      a manifest equal to the running one).
    - **The helper's tools live in the runtime image.** It runs the CNI
      plugins, iptables and the mount tools as root, so they cannot come
      from a folder the agent writes. The runtime image grows from about
      364 MB to 561 MB, and a bump of one of those tools is now a runtime
      image change, which a split worker takes only through a decommission.
      The mount tools' user is made by the runtime container's start
      command, and only when external storage is on: the helper serves
      mounts only when that user exists, which keeps an off switch.
    - **One shared folder.** The helper hard-links each ready socket the
      agent makes into a folder of its own, and a link cannot cross mounts.
      So one emptyDir, `/run/aerolvm-rootd/shared`, holds the helper's
      socket, ready sockets and task FIFOs and the agent's run folder
      (`SB_MOUNTS_CRED_DIR`). The kubelet makes an emptyDir open to all,
      which the helper refuses (internal/rootfolder), so `split-folders`
      makes it root's (0750, the agent's group) before any other
      container starts (see below).
    - **The agent cannot see its sandboxes' cgroups.** A container that is
      not privileged gets its own cgroup namespace, and the sandboxes'
      group is the runtime container's. Capacity sizing (C7), the live
      memory probe and usage metrics (C20) read it, and `sandboxd` would
      not start. The split agent mounts the machine's `/sys/fs/cgroup`
      read only; `aerolvm k8s verify` allows exactly that mount and nothing
      wider. Owner decision (below): a helper call that reads these files
      would remove the mount.
    - **The disk floor reads the sandbox volume through one empty folder on
      it** (a read-only `subPath`), as the agent no longer mounts
      containerd's root.
    - **The egress gateway lets in uid 65531** (`SB_EGRESS_PEER_UIDS`).
    - **What split refuses at `helm install`** (aerolvm.splitGaps): the
      daemon's gaps (Firecracker, gVisor moves, the containerd warm pool,
      which the kubectl API's warm pools use) and, for this chart only,
      WASM and V8 isolates. Those run in split on VMs (PR 9a); a split
      worker pod still needs the deny floor stamped into the runtime
      container (the operator stamps it into the agent and egress only),
      the WASM socket folder on the shared folder, the V8 jail's base
      outside the agent's folders, and a live check of host adoption
      without a shared process namespace. gVisor moves default to off in
      split and on in single. pkg/daemon's chart tests read
      `checkPrivilegeMode`'s source, so a new daemon gap fails CI until
      the chart refuses it too.
    - **Switching a running install** is a decommission per worker in
      cluster mode and a pod delete in single mode (the NOTES and the Operate
      page say how). A state volume that outlives the pod keeps files the
      root agent wrote, which the split agent cannot open: the switch
      starts from a new volume.
    - **No root process writes in a folder the agent can write** (review
      of #1424). The supervisor wrote the cgroup parent into `/run/aerolvm`,
      which the agent writes too, at a fixed temporary name. Now it writes
      to a folder of the runtime container's (`/run/aerolvm-runtime`), which
      the agent mounts read only, by `O_EXCL` temporary file and rename; the
      runtime container mounts every folder the agent writes read only, or
      not at all (the state volume); the supervisor reads the ownership
      lease as a regular file through no link; and the owners of the
      shared folders are set by a first container, `split-folders` (root,
      `CAP_CHOWN` only), before the agent or the helper starts. The shared
      folder stays the one volume both write: its top is root's, and the
      agent writes only its own folder in it.
      The review of #1424 then found the egress container: it starts as
      root (and drops to 65532), and the gateway made its control socket,
      and set its mode, by name in `/run/aerolvm`. Now the socket lives in
      a folder of the egress container's own (`/run/aerolvm-egress`, which
      `split-folders` gives to 65532 with mode 0755), the agent mounts that
      folder read only and still dials the socket, and the egress container
      mounts `/run/aerolvm` read only. The gateway refuses to make a socket
      open to another uid in a folder another user can write. Each folder
      each root container writes, in split:
      - `split-folders`: the tops of `state`, `rootd-shared`, `cni-state`
        and `run-egress` (owners and modes), and `rootd-shared/agent`,
        made after that folder's top is root's. It runs before every other
        container.
      - `runtime`: `run-runtime`, `rootd-shared` (only the helper's own
        folders), `cni-state`, `run-containerd` and containerd's volume.
      - `egress`: `run-egress` (the control socket) and `egress-state`.
      A chart test checks every container that starts as root, and fails
      when a new one appears.
    - **Kind found three more things** the offline tests could not: the
      agent may not change the mode of an emptyDir's own folder
      (`/run/sandboxd`), the helper refuses the CNI records' emptyDir
      until root closes it, and the egress gateway made its control socket
      0600 for its own uid, so a split agent could not dial it (the gateway
      now opens it when it answers another uid, as sandboxd's lookup socket
      does). Reading the code found a fourth: in enterprise mode the split
      agent must be in the edge's group to hand it the public API socket.
    - **Proven on kind** (Docker Desktop, kernel 5.10;
      `integration-tests/k8s/split.sh`): the pod's shape, runc and gVisor,
      files, the worker's ports and the Kubernetes API closed, no-network,
      address and hostname allow lists, an rclone mount, an agent restart
      and a helper restart with every sandbox kept, `aerolvm k8s verify`,
      a pod delete with nothing left behind, `auto` on upgrade and install,
      the edge (HTTPS API, sandbox links, a certificate renewal, a raw TCP
      port) in split, and single mode's smoke test on the new images. CI's
      kubernetes job now runs split on kind too. Not on kind: memory
      pressure (F10) and create latency (N1), which need a real node; the
      cluster-mode mixed fleet (one kind node cannot hold three servers,
      three gateways and two workers beside the other local clusters); and
      a 6.12 kernel. Those are the EKS drill's.
12. Docs, `EVIDENCE.md` and the capability matrix.

### 3.6 Tests

- **A "broken agent" suite.** A test client calls the helper and the gate
  directly, as a compromised agent would. Every hostile request must be
  refused: a privileged spec, a bind mount of `/`, a hook, `BinaryName=/bin/sh`,
  `dev.gvisor.flag.network=host`, a netns ID with `../`, a cgroup path outside
  the parent, a mount option that adds a flag to a root-run mount tool, a
  caller with the wrong uid. This list goes into `EVIDENCE.md` as the proof for buyers.
- Table tests and fuzz tests for `internal/rootpolicy`. Each package keeps
  85% line coverage or more.
- Offline: the agent against a fake helper; the helper against fake kernels
  (the netns and netrules packages already have fakes).
- Kind (tag-gated): a worker whose agent container runs as 65532 with no
  capabilities passes the gVisor, runc, WASM, V8 and Firecracker proofs.
- Live, one EKS run: S2 (agent swap keeps sandboxes), OV-E2 (external mount
  across the swap), F8 (no leaked namespaces after a pod delete), and the
  N1 benchmark to measure create latency before and after.

- **Regression contract** (eng review D10). These already work and must
  not change: S2 (sandboxes keep running across an agent swap), OV-E2 (an
  external mount reaches the sandbox and survives the swap), F8 (no leaked
  namespaces after a pod delete), F10 (memory pressure kills one sandbox,
  never the machinery), egress rules, node guard, floor, IPv6 fence and the
  metadata block, the TCP host-port pool (with a regression test in the
  `store_test.go` / `layer4_bootstrap_test.go` style and a PR call-out),
  WASM, V8 and Firecracker create, exec and adoption after an agent
  restart, gVisor and Firecracker moves, and a VM single-node install and
  upgrade. Intended differences: the agent runs as uid 65532 with no
  rights, namespaces are made in the `runtime` container, external storage
  is on by default. Proof: offline tests against a fake helper, every
  existing kind proof on the split worker, and one live EKS drill (S2,
  OV-E2, F8, F10, N1) before the chart flips.

### 3.7 Boot path (CLAUDE.md non-negotiable 2)

A create now makes a few calls over a local socket: `Realize` (skipped on a
warm-pool hit, whose slot is already realized),
`ApplyEgressPolicy`, `MarkOOMVictim`, plus the gate's check on the container
create. `ResolveImageUser` is cached per image digest, so it is not on the
warm path. Each call should cost well under a millisecond. Budget: at most
+1 ms p50 on a warm create and +3 ms p50 on a cold create, measured with the
N1 script before and after. The PR that wires the first call states the
numbers, including the first create after the helper starts.

The helper serves calls in parallel (eng review D11). Calls for one sandbox
run in order under a per-sandbox lock; shared kernel objects keep only the
locks they have today (for example netrules' block-set connection,
`pkg/docker/netrules/netlink_backend.go:49`). The PR that wires the first
call adds a 100-parallel-create benchmark, p50 and p99 against today's
in-process path, within the budget above.

---

## 4. M2: a hardware wall on ordinary EKS machines

### 4.1 Two ways, side by side

| | (a) KVM Firecracker, nested virtualization | (b) Firecracker through Nitro, direct mode |
|---|---|---|
| Machines | Intel 7th and 8th gen (M7i, C7i, R7i, M8i, C8i, R8i and others) with `CpuOptions.NestedVirtualization=enabled` | Any supported 5th-gen or newer: Intel, AMD, Graviton. No metal. |
| Node setup | One launch setting. Karpenter's `EC2NodeClass` has it. | Launch with Nitro Enclaves on, plus a boot-time memory pool (kernel argument and reboot). Custom AMI or first-boot step. |
| Snapshots, pause, moves, warm pool | **Yes**, as on metal today | No snapshots, pause or moves (AWS limit). A snapshot warm pool is impossible; a pool of pre-booted, parked VMs is possible (eng review D21) |
| Density | Like metal, minus nested overhead (not measured yet) | At most 5 VMs per vCPU, 896 per machine. Whole cores on SMT machines. |
| Smallest VM | Ours (no minimum enforced today) | 256 MiB |
| Speed | Bare cold boot 820–860 ms (S6). Warm pool and snapshot restore not measured under nesting. | Not measured. The AWS EKS sample: 3.2–3.7 s per cold pod, through their whole stack. |
| Leads to M3 | No | **Yes:** the same VM in confidential mode |
| Status | S6 pass; kind pass; never on EKS | Not tried |

A node cannot have both nested virtualization and Nitro Enclaves. So (a) and
(b) are separate node pools. Both pools can still run gVisor sandboxes next
to their VMs, so neither needs a pool of its own just for Firecracker.

**We recommend both.** (a) keeps everything Firecracker does today and is
nearly built. (b) reaches the machines (a) cannot, and it is the only road
to M3.

### 4.2 Spikes first (Phase 0 style, about $10 together)

**SP-A, (a) on EKS** (the Kubernetes plan's N7 and C3). Run the `fckind.sh`
proofs on an EKS node pool of m8i.xlarge with nested virtualization: cold
create, template-snapshot create, warm-pool create, pause and resume, a
move. Run the same script on a c5.metal for the comparison S6 asked for.
Go if warm create stays under 100 ms p50 and pause/resume and moves pass.

**SP-B, (b) by hand, then in a pod.** One m7i.xlarge launched with Nitro
Enclaves on, AL2023 kernel 6.18.51-120.162 or later, a 4 GiB pool.

1. Firecracker v1.18 under our jailer argv, `PUT /enclave {"direct_mode": true}`,
   an EFI `bzImage` guest kernel with virtio-pci, our toolboxd rootfs. Time
   from start to toolboxd answering on vsock port 1024.
2. TAP networking with our nft egress rules on the TAP.
3. Confidential mode with a DMB-patched kernel and `CONFIG_NSM`: get an
   attestation document from `/dev/nsm` and check it against the AWS root.
4. 50 creates in parallel; the 5-per-vCPU cap; what happens past it.
5. Does the parent use the pool's memory while no VM runs? (The docs call
   it a CMA pool. If not, that memory is lost to gVisor sandboxes.)
6. Does the guest see a vmgenid device?
7. The same steps inside a privileged worker pod on an EKS node launched
   with Nitro Enclaves on. How do the device and the PCIe slot setting
   (`/sys/class/misc/nitro_enclaves/pcie_slots`) reach the pod? Does
   Karpenter's `EC2NodeClass` set enclave options, or do we need a launch
   template?

Go if steps 1–4 pass and a cold create is under 2 s end to end. Write the
numbers into this plan, as the Kubernetes plan does for its spikes.

**Results so far (2026-11-20, partial).** SP-A ran on plain EC2 machines,
not an EKS node pool: sandboxd from main 04552baa0, KVM Firecracker, 20 runs
per step. SP-B did not produce numbers: its machine came up, but the run
stopped before step 1.

| SP-A, p50 (p99) | c5.metal, bare metal | m8i.xlarge, nested virtualization |
|---|---|---|
| Cold create (image → rootfs → boot) | 1,322 ms (1,360) | 1,376 ms (1,605) |
| Template-snapshot create | 54 ms (1,354) | 88 ms (428) |
| Pause (stop writes a memory snapshot) | 5,395 ms | 4,262 ms |
| Resume (start restores it) | 1,360 ms | 445 ms |
| First exec after resume | 4.4 ms | 11.4 ms |
| Pause/resume cycles intact | 20 of 20 | **14 of 20** |
| Warm-pool create | not measured | not measured |
| Move | not run | not run |

- **Nested resume loses sandboxes.** On the m8i, 6 of 20 starts failed with
  `vsock handshake: vsock read: EOF` and a retry did not help: those
  sandboxes were lost. The c5.metal lost none. This fails SP-A's
  "pause/resume pass" bar, and has to be explained before (a) ships. It may be
  a guest-side vsock timing problem under nested virtualization, not a
  hardware limit.
- **Warm pool not measured.** Every warm spawn failed on both machines with
  `LoadSnapshot ... rootfs.ext4: No such file or directory`, so all 20
  creates missed the pool. Whether that is the spike's setup or a bug in
  the warm-VMM pool's snapshot path is not known yet.
- **Spend:** at most about $5 of the $15 the owner approved: six instances
  (CloudTrail launch and terminate times; the c5.metal ran 11 minutes, the
  others shut themselves down within hours). Every `owner=aerolvm-spike`
  instance is terminated.
- **Next:** rerun SP-A with the warm pool fixed and moves added, chase the
  nested vsock EOF, then run SP-B steps 1–4. Until then neither (a) nor (b)
  has a go.

### 4.3 Building (b): one driver, two backends

| Change | Where |
|---|---|
| New settings: `SB_FIRECRACKER_BACKEND=kvm\|nitro` (per node, default `kvm`) and `SB_FIRECRACKER_NITRO_MODE=direct\|confidential`. A Nitro node offers a new runtime name, `firecracker-nitro` (final name settled in the PR); `runtime: "firecracker"` keeps meaning today's KVM VM, and a create is never moved to another backend silently: if no node offers the runtime it asked for, it gets a clear error (owner requirement R18) | `internal/config/config.go`, `pkg/models` runtime constants, `internal/cluster/placement.go` |
| **The KVM backend keeps today's v1.15.1** and its whole fast path (owner requirement R18). v1.18.x ships only on Nitro node pools; Nitro and nested virtualization or metal never share a machine, so each pool carries its own binary. If the KVM backend is ever moved to v1.18 later, D16's rule applies then: each sandbox snapshot records its Firecracker version and restore runs that version's binary until no v1.15 snapshots remain. | `packaging/images/versions.env`, `scripts/install.sh`, `Terraform/variables.tf`, `Ansible/` |
| `PutEnclave` call before `InstanceStart` | `pkg/firecracker/client.go`, `driver.go:configureVMM` |
| No `TrackDirtyPages` and no vmgenid check on Nitro | `driver.go:configureVMM`, `validateVMGenIDCapability` |
| A second guest kernel: EFI `bzImage`, virtio-pci, PCIe hot-plug; for confidential mode, the DMB patches and `CONFIG_NSM`. **New pipeline:** AerolVM builds no guest kernel today; it pins Firecracker CI's v1.15 `vmlinux` 5.10.245 by SHA-256 (`scripts/install.sh:265-272`). M2 (b) adds a kernel build in CI, published per release with its config and checksum; M3 needs that build to be reproducible. | New CI job; `packaging/images/versions.env`, `scripts/install.sh`, `Terraform/variables.tf` |
| **Stop keeps the disk and drops memory. Start cold-boots from the kept disk**, on the same TAP slot. Pause answers `409 pause_unsupported` with a reason. A move uses the disk (as the containerd engine does) or recreates, per the decommission policy. | `driver.go:Stop/Start`, `sandbox_move.go`, `internal/service/lifecycle.go` |
| **Parked warm pool for Nitro** (eng review D21): each Nitro node pool can keep N VMs per image booted ahead of time, with toolboxd waiting inside; a claim does the vsock handshake, pushes env and adopts the guest, the same steps a Firecracker create already ends with. Off by default; pool size set per Nitro node pool and image. Parked VMs count toward the 5-per-vCPU and memory-pool limits. Today's KVM snapshot warm pool is untouched. SP-B times a parked claim. | `internal/runtime/firecracker/` (new parked-pool path for the Nitro backend), `internal/pool/vmm/`, chart values |
| Admission: at most 5 VMs per vCPU and 896 per machine; at least 256 MiB, in 2 MiB steps; even vCPU counts on SMT machines; memory counted against the pool, not the machine. Refusals are capacity errors (`429`), as today. | `pkg/capacity/capacity.go` |
| Preflight: `/dev/nitro_enclaves`, the pool in the kernel log, kernel version, PCIe slots | `internal/nodejoin/pod_preflight.go`, `preflight.go` |
| Chart: `worker.firecracker.backend: nitro`; the device in the `runtime` container | `charts/aerolvm/values.yaml`, `_workerpod.tpl` |
| EKS stack and Terraform: a Nitro node pool (enclave options, the pool, the AMI step from SP-B) | `Terraform/`, the one-click EKS stack |
| Placement: a create that asks for Firecracker goes to a node whose backend fits. Uses the existing runtime-aware placement. Cluster call-out: no FSM change. | `internal/cluster/placement.go` (tests next to it) |
| Docs: a new page, `hardware-isolation-on-eks.mdx`, five SDK tabs | `docs/src/content/docs/`, `docs/src/content.config.ts` |

### 4.4 Building (a)

This is N7 and C3 from the Kubernetes plan, already scoped there: the
Firecracker worker pool on EKS, its warm pool turned on in that pool, and
the numbers from SP-A. The only new part is a docs section that explains
when to pick (a) or (b).

---

## 5. M3: a confidential tier with attestation-gated secrets

### 5.1 What "confidential" must mean for us

The threat: someone with root on the **worker machine**, or a broken agent
or root helper. The control plane (servers and gateways) and the customer's
key custody are trusted, as today. The goal is that worker root cannot read:

1. the sandbox's memory (Nitro confidential mode does this);
2. its secrets: env, registry credentials, cloud tokens;
3. what it writes to disk;
4. what it sends and receives, including exec and file traffic.

Nitro on EKS covers 1 and 3. It refuses exec and leaves Pod Identity, CSI
secrets and EBS visible to the host. We can cover 1, 2 and 3 in v1, and 4 in v2.

### 5.2 The pieces

1. **Confidential VMs.** M2 (b) with `SB_FIRECRACKER_NITRO_MODE=confidential`.
2. **A measured guest.** AerolVM publishes, with every release, a guest
   kernel and initrd built reproducibly, and their PCR0, PCR1 and PCR2,
   signed with cosign. The initrd's first program (`aerolvm-guest-init`,
   built from `cmd/toolboxd`'s tree) extends:
   - **PCR16** with the image's manifest digest;
   - **PCR17** with the sandbox's confidential profile (which host
     operations are allowed; see point 5);
   - **PCR18** with the sandbox ID and owner,
   before it runs any tenant code. EKS does the same with its Cedar policy
   in PCR17.
3. **The image is checked inside the guest.** A confidential create must
   name its image by digest (`image@sha256:…`). v1: the host hands the
   guest the image's layers on a read-only drive. The guest checks each
   layer against the manifest and unpacks it onto its writable disk. That
   disk is encrypted with `dm-crypt`, with a key from the NSM's random
   source that never leaves the guest in the clear. **The disk key is
   wrapped by KMS** (eng review D19, which replaces D15's refusal): at first
   boot the guest encrypts its disk key with the customer's KMS key, as its
   own team role, with the encryption context `sandbox=<id>, purpose=disk`;
   the host keeps only that ciphertext next to the disk. On a cold Start,
   or after a disk-only move, the guest attests again and gets its key back
   only through the same checks as every secret (D12's PCR16/17/18/4 checks
   before its OIDC token; D13's session-tag match in KMS), answered as
   `CiphertextForRecipient`. So Stop and Start work for confidential
   sandboxes, with the disk kept and memory lost, as for direct-mode Nitro
   (§4.3); a move carries the disk and its wrapped key. Pause still answers
   `409` with a reason, because Nitro cannot snapshot. Cold creates get slower; SP-B
   measures by how much. v2: `dm-verity` over a reproducible `erofs` image,
   with its root hash in PCR16, so the host can cache images again.
4. **Secrets are opened only inside the guest.**
   - **With AWS KMS custody** (`pkg/secrets/awskms.go`): the env's data key
     is wrapped by the customer's KMS key. The key policy lets AerolVM's
     servers wrap (`GenerateDataKey`, `Encrypt`) but allows `Decrypt` only
     with `kms:RecipientAttestation:ImageSha384` (PCR0) and the PCR17
     values of the profiles the customer allows. The KMS encryption context
     carries the sandbox ID, so one sandbox's env cannot open in another.
     The guest asks KMS itself, over TLS, through the worker's network. The
     worker carries only ciphertext. **After sealing, not even our servers
     can read that env.**
   - **Whose identity signs the KMS call** (eng review D7): the sandbox's
     own. The server mints the sandbox's OIDC token
     (`internal/cloudidentity`) and encrypts it to the guest's attested key;
     the guest swaps it for the customer's team role with
     `AssumeRoleWithWebIdentity` and calls `Decrypt`. The key policy names
     that team role as the only `Decrypt` principal, with the attestation
     conditions above, and a `Deny` on any `Decrypt` that carries no
     attestation document. CloudTrail names the team role on every release.
     The token also carries the sandbox ID as an AWS session tag (the
     `https://aws.amazon.com/tags` claim), and the key policy requires
     `kms:EncryptionContext:sandbox` to equal `${aws:PrincipalTag/sandbox}`,
     so KMS refuses a guest that asks for another sandbox's secret (eng
     review D13). The M3 live test checks that a cross-sandbox `Decrypt` is
     refused.
     So the confidential tier needs per-sandbox cloud identity turned on and
     an IAM trust for AerolVM's issuer in the customer's account; the docs
     page walks through both.
   - **With Vault, OpenBao or a PKCS#11 HSM:** these do not read Nitro
     documents. The server checks the document itself: COSE signature,
     chain to the AWS Nitro root, PCR0 equal to a published value, PCR16
     equal to the image digest the control plane recorded at create (eng
     review D12), PCR17 an allowed profile, PCR18 the right sandbox, PCR4
     the instance the sandbox was placed on, a fresh nonce. Then it sends the env encrypted
     to the key in the document.
   - **Cloud tokens** (`internal/cloudidentity`): the server mints the
     token and encrypts it to the guest's attested key, only after the same
     check, PCR16 included. Because the guest can reach KMS only with this
     token (D7), every secret release passes the image check (D12). The worker never
     sees it. On EKS the host "can mint Pod Identity credentials for any
     pod"; here it cannot read even one sandbox's token.
   - **Registry credentials** for the image pull stay on the host in v1.
     The image content is not secret in v1. Encrypted images are a later
     item.
5. **Host operations.** toolboxd in the guest enforces the profile in PCR17.
   Because it is measured, the host cannot change it.
   - **v1:** the default profile refuses exec, file reads and writes,
     sessions and process lists from the host, as EKS does. Logs are a
     profile choice. The sandbox runs its entrypoint and talks to the world
     over its own TLS.
   - **v2:** an end-to-end channel. toolboxd ends TLS inside the guest,
     with a key bound into an attestation document. Each SDK (all five)
     checks the document against the published PCR0 and the sandbox's own
     PCR17 and PCR18, then sends exec and file calls over that channel. The
     worker and gateways pass the bytes through without reading them, as
     Caddy already passes TLS through by name. Then exec and files work
     again, and the host still sees nothing. **No rival does this.**
6. **Egress.** Hostname filtering keeps working: it reads DNS and SNI, not
   content. **TLS inspection and credential injection are refused** for a
   confidential sandbox at create, with `409` and a reason, because both
   decrypt traffic on the host (`internal/service/egress_inspect.go`).
7. **Audit.** Every attestation check goes into the hash-chained audit log:
   the document's hash, the PCRs, the result, the nonce. `aerolvm audit
   verify` covers it. A customer can prove what ran with their secrets.
8. **Optional: worker machines prove what they booted (M3c).** NitroTPM
   attestable AMIs. The join flow (§15.2 of the Kubernetes plan) would also
   need a NitroTPM document whose PCR4, PCR7 and PCR12 match an approved
   AMI before the node gets its certificate. It means building and shipping
   our own attestable EKS worker AMI with KIWI NG. Large ops cost. Build it
   only when a buyer asks.

### 5.3 Limits to state plainly

- AWS only.
- No snapshots, pause or moves with memory (Nitro).
- The host still carries the device traffic and decides when the VM runs.
  Network secrecy needs TLS inside the guest. Availability is not protected.
- Debug mode zeroes the measurements. Every key policy must pin PCR0, never
  PCR3 or PCR4 alone (AWS's own warning).
- Confidential mode rejects the entropy device. The guest seeds its random
  pool from the NSM.
- At least 256 MiB plus 16 MiB per virtual device per VM.

### 5.4 The PRs, in order

v1: the guest kernel and initrd build with published PCRs; `aerolvm-guest-init`
and the PCR16–18 measurements; toolboxd profiles; layers checked and
unpacked in the guest, with an encrypted disk; KMS release with
`CiphertextForRecipient`; the server-side document checker for the other
custody providers; cloud tokens encrypted to the guest; refusing inspection
and injection; attestation in the audit log; a `confidential` create field
in the API and all five SDKs (`/add-v1-endpoint`, `/add-sdk-method`); docs
page `confidential-sandboxes.mdx`.

v2: the in-guest TLS channel and its checks in all five SDKs; `dm-verity`
images.

M3c: on request.

---

## 6. M4: an install with no privileged pod ("pod mode")

### 6.1 The shape

- One chart value: `install.mode: pod`. Gateways, servers and the operator
  do not change; they already run with no special rights.
- The worker is a **StatefulSet** of unprivileged pods (`restricted` Pod
  Security). Each replica is one AerolVM worker with a stable identity.
  Its `sandboxd` uses a new runtime driver, `internal/runtime/kubepod`,
  that makes one Kubernetes pod per sandbox.
- Sandbox pods live in their own namespace, with Pod Security `baseline`
  (images that run as root still work) and a `ValidatingAdmissionPolicy`
  that refuses any pod there without an allowed `runtimeClassName`.
  Plain `runc` is refused unless the operator turns it on for trusted code.
- The RuntimeClass comes from a map in the chart: `gvisor`, `kata-qemu`,
  `isolated-sandbox`, `confidential-sandbox`, or the cluster's own names.
  On EKS, picking `isolated-sandbox` gives a hardware wall with no
  privileged pod. That covers M2's row in this mode without M2's work.

### 6.2 The `kubepod` driver

It implements `runtime.Runtime` (`internal/runtime/runtime.go`).

| Call | What it does |
|---|---|
| `Create` | One pod named after the sandbox ID (so a retry finds it: idempotent). Requests equal limits. No service account token, no host paths, no host network. An init container copies toolboxd into an `emptyDir`; the main container starts toolboxd, which then starts the image's own entrypoint (read from the registry by the worker, no root needed). |
| Env and trust | **Nothing secret in the pod spec**, because that goes to etcd in the clear. toolboxd starts parked. It trusts only the cell's worker CA (a public certificate in a ConfigMap) and only the worker named in its pod spec (a node ID, not a secret). That worker's first mTLS call pushes the toolbox token and env together, the way the containerd warm pool already hands env over (`internal/runtime/containerd/warm_adopt.go`). Read access to pods reveals no credential (eng review D8). |
| `Start` / `Stop` | Stop deletes the pod and keeps its volume if it has one. Memory is not kept, as with agent-sandbox and Nitro. |
| `Inspect` / `ListManaged` | One informer on the namespace, filtered by this worker's label. No polling. A worker restart finds its pods again. |
| Warm pool | Parked pods per image. A claim is an env push plus start. **No Kubernetes write per claim.** A cold create costs one pod create and one delete, against about 23 objects in agent-sandbox. |

RBAC: one Role in the sandbox namespace (pods: create, delete, get, list,
watch). No rights anywhere else. agent-sandbox's controller has
cluster-wide rights (its issue #1440).

### 6.3 Egress without a worker firewall

- The chart's NetworkPolicy for the sandbox namespace: no ingress except
  from workers and gateways; egress only to AerolVM's egress gateways and
  its filtering DNS; the metadata address blocked.
- Hostname filtering: toolboxd sets the proxy env so traffic goes through
  the egress gateway, which applies each sandbox's rules. Traffic that
  ignores the proxy is dropped by the NetworkPolicy (fail closed). Where the
  cluster has a CNI with name-based policy (Cilium `toFQDNs`, EKS Auto Mode
  `ApplicationNetworkPolicy`), the driver writes that instead.
- The gateway maps each pod IP to its sandbox, so every decision is logged
  with the sandbox ID. Each sandbox has its own VPC address, so the buyer's
  flow logs can tell sandboxes apart. Pod mode closes the matrix's S3 gap
  for this install.

### 6.4 What changes against the default install

| | Default install | Pod mode |
|---|---|---|
| Privileged pods | One container (`runtime`) after M1 | **None** |
| Cold create | 232 ms p50 (gVisor, EKS) | About agent-sandbox's: 1–4 s, depending on the RuntimeClass |
| Warm create | 19 ms | Env push plus start; to be measured |
| Sandboxes per machine | 1,000 (m7i.4xlarge) | The pod limit, or 5 per vCPU on Nitro |
| Kubernetes writes per sandbox | 0 | 2 cold, 0 warm |
| Snapshots, moves with memory | Yes | No |
| Egress by hostname, audit, sealed env, SSO, SDKs, facades | Yes | Yes |

Cluster call-out: no FSM change. A pod-mode worker reports capacity from a
configured quota. Failover recreates, because a rescheduled pod is a new
sandbox, but only behind a fence (eng review D17), the pod-mode copy of
`LeaseGuard` (`internal/supervisor/lease.go`): toolboxd is PID 1 of the
sandbox container (`restartPolicy: Never`) and holds a lease its worker
renews over the D8 mTLS link; when the lease lapses it ends the sandbox's
processes. The new owner recreates only after Kubernetes confirms the old
pod is gone, or after the lease has lapsed plus a grace period. So two
copies never run at once, even with the old node unreachable, and the new
pod never clashes with a surviving one of the same name.

### 6.5 Tests

Offline: the driver against client-go's fake clientset. Kind (tag-gated):
gVisor as a RuntimeClass, the full create, exec, files, egress and warm-pool
proof. Live: EKS Auto Mode with `isolated-sandbox`, and the N1 benchmark for
the numbers in 6.4.

---

## 7. Order of work

| Step | What | Size | Cost of live runs |
|---|---|---|---|
| 1 (now) | M1 quick wins Q1–Q4 | 4 × S | none |
| 1 (now) | M1 PRs 1–3 (rules, socket, containerd gate) | M | none |
| 1 (now) | Spikes SP-A and SP-B; numbers written here | S | about $10 |
| 1 (now) | M4 design review (this section 6) | S | none |
| 2 | M1 PRs 4–12, then one EKS drill | L | about $10 |
| 2 | M2 (a) on EKS (N7, C3) | M | about $10 |
| 3 | M2 (b) Nitro backend | M–L | about $10 |
| 4 | M3 v1 | L | about $10 |
| 5 | M4 build, when a buyer refuses privileged pods, or after M1 if the owner wants it sooner | M–L | about $10 |
| 6 | M3 v2 (SDK channel); M3c on request | L | about $10 |
| 1 and 3 | Discoverability (§11): PRs 1 and 5 now for today's runtimes; PRs 2–4 with M2 (b) | M | none |

Live-run costs are estimates from earlier runs of the same harness (all of
Phase 0, twelve EKS clusters and two S6 instances, cost about $8.70). Every live run follows the repo's rules:
builds go to nodes through S3 (`integration-tests/scripts/stage-to-node.sh`),
never `scp`, and `make integration-reap` runs after.

Each item is done when its live proof passes, `EVIDENCE.md` says so, and the
capability matrix row is updated.

---

## 8. The repo's hard rules, applied

| Rule (CLAUDE.md) | Where it bites | What we do |
|---|---|---|
| 1. Idempotency | Every helper call; `kubepod.Create`; KMS release | Ensure/remove calls; pod name = sandbox ID; release keyed by sandbox and nonce |
| 2. Boot-path latency | M1 (new socket calls), M2 (b) (enclave call), M3 (layer check in guest), M4 (pod create) | Each PR states p50 and p99 before and after, and the first create after start |
| 3. Lazy bootstrap | The agent's link to the helper | `atomic.Bool` plus `sync.Mutex`, as `EnsureLayer4Ready` |
| 4. Failure-path consistency | M1 network then firewall then container; M4 pod then env push | Each multi-step create rolls back in reverse order; documented per PR |
| 5. TCP pool and L4 | `EnsureHostPort` moves into the helper | Regression test in `store_test.go` / `layer4_bootstrap_test.go` style, and a call-out |
| 6. Cluster mode | M2 placement by backend; M4 worker capacity | Tests next to `placement.go`; no FSM change; `Noop` path unchanged |
| Coverage 85% | Every new package | `/maintain-coverage` before each PR |
| `make test` stays offline | All | Live work behind the `integration` tag |
| Docs | M2, M3, M4 are new features | One new `.mdx` page each, five SDK tabs, no curl |

---

## 9. Risks

| Risk | Effect | What we do |
|---|---|---|
| The containerd gate misses a field | A broken agent gets root | Allow by name and refuse the rest. Fuzz tests. Re-read the gate on every containerd bump. The "broken agent" suite runs in CI. |
| The helper grows | It stops being small, changes often, and each change costs a drain on Kubernetes | A rule in review: the helper takes typed inputs and checks them; logic stays in the agent. Count its lines in CI and flag growth. |
| Firecracker v1.18 changes something we rely on | The KVM path breaks | SP-A runs the full Firecracker proof on v1.18 first. Snapshots are rebuilt. |
| The Nitro pool memory is lost to gVisor | Fewer sandboxes per node | SP-B step 5 measures it. Size the pool per node pool. |
| Guest-side image checks make confidential cold creates slow | Seconds per create | v1 accepts it (EKS's own is 3–4 s); v2 brings `dm-verity` caching |
| Buyers need exec in confidential sandboxes before v2 | v1 is not enough for agent work | v2's SDK channel is the answer. Say so up front. |
| Pod mode speed disappoints | Buyers compare it to the default | Sell it only to buyers who refuse privileged pods. Publish its numbers next to the default's. |
| AWS changes Nitro Sandboxes (launched 10 days ago) | Plan details go stale | Re-read the AWS pages at the start of M2 (b) and M3 |

---

## 10. Decisions for the owner

1. **M2: both backends, or Nitro only?** Settled 2026-11-20 by the owner's
   add-on rule (eng review R18): both. KVM stays the default and unchanged;
   Nitro is an extra runtime, `firecracker-nitro`.
2. **M3 v1 without host exec and files: acceptable to first buyers?**
   Recommended: yes, as EKS does, with v2 on the plan.
3. **M3 key policy: may our servers wrap but never unwrap env?**
   Recommended: yes, for KMS custody. It is the strongest claim we can make.
4. **M4: build now, or keep the `TODOS.md` trigger?** Recommended: design
   review now, build on a buyer's request or right after M1.
5. **Docker engine (local mode) stays outside M1?** Recommended: yes, and
   the docs say so.

---

## 11. Discoverability: how people find and pick each option

Added 2026-11-20 at the owner's request; approved in full (eng review D23).

**What exists today.** Each node already tells the scheduler which runtimes
it can run (`supported_runtimes` in its capacity heartbeat,
`pkg/capacity/capacity.go:206`; placement uses it in
`internal/cluster/placement.go:558`). `GET /v1/capacity` shows one node's
list. The runtime names live in `pkg/models/types.go:161` and the check that
accepts them at `pkg/models/types.go:304`. The Kubernetes view shows the
runtime name as the `runtimeClassName` (`internal/kubeapi/render.go:62`).
**What is missing:** nothing tells a caller which options *this cluster*
offers, what each can do (snapshots, pause, warm pool, confidential), or
how to turn one on. The docs have one page per runtime and no page that
compares them. Once Nitro lands there are two Firecracker options, and
nothing says which is which.

**Who needs to find what:**

| Who | Question | Where the answer is |
|---|---|---|
| A developer (SDK, CLI or agent) | Which runtimes can I ask for here, and what does each do? | `GET /v1/runtimes`; `runtimes.list()` in all five SDKs; `aerolvm get runtimes`; an MCP tool `list_runtimes` so agents can choose |
| A developer after a create | Which backend did I get? Was it a warm start? | New sandbox fields `backend` (`kvm`, `nitro`) and `warm` (`snapshot`, `parked`, `none`), next to today's `runtime` and the `Server-Timing` header |
| A developer who asks for something missing | What can I use instead? | The refusal names the runtimes this cluster offers, never a silent swap (R18) |
| An operator | Which options does each node pool offer, and why not the others? | The worker preflight and `aerolvm k8s verify` print, per pool, what they found (KVM, nested virtualization, Nitro Enclaves and its memory pool) and which runtimes the node will offer; the chart's install notes list the enabled options; `aerolvm get nodes` shows runtimes, backend and `privilegeMode` |
| A Kubernetes user | Which `runtimeClassName` values work? | The same names as the API (the mapping is already 1:1); the docs list them |
| An evaluator (a bank) | What does each option protect against, and at what cost? | One docs page comparing the options, and the same table in `charts/aerolvm/EVIDENCE.md` |

**The runtimes list.**

```
GET /v1/runtimes
{"runtimes": [
  {"name": "firecracker", "isolation": "hardware-vm", "backend": "kvm",
   "features": {"snapshots": true, "pause": true, "moves": "memory",
                "warm_pool": "snapshot", "confidential": false},
   "available": true},
  {"name": "firecracker-nitro", "isolation": "hardware-vm", "backend": "nitro",
   "features": {"snapshots": false, "pause": false, "moves": "disk",
                "warm_pool": "parked", "confidential": true},
   "limits": {"min_memory_mb": 256, "max_per_vcpu": 5},
   "available": true},
  {"name": "gvisor", "isolation": "user-space-kernel", ...},
  ...
]}
```

- Read-only. Gateways answer it from the capacity data the cluster already
  holds; no call to workers, no new writes. Single-node installs answer it
  from their own capacity.
- Tenants see names, features and whether any capacity exists. They never
  see node names or pool sizes, the same rule `GET /v1/capacity` already
  applies to templates and warm pools. Fleet admins also see each pool's
  free capacity.
- **One table in code** (next to the runtime names in `pkg/models`) holds
  each runtime's features and limits. The API, the create error and the
  docs table all come from it; a test fails when the docs page's table and
  the code table disagree, so they cannot drift apart.
- `GET /v1/runtimes` is a new read-only route. v1 is soft-frozen, but this
  adds without changing anything, so it goes through `/add-v1-endpoint`
  and its PR says so.

**Docs.** One new page, `choose-isolation.mdx`: the comparison table (KVM
Firecracker, Nitro Firecracker, gVisor, runc, WASM, V8, confidential, pod
mode), with speed, density, features, where each runs, how an operator
turns it on, and how a create picks it, in the five SDK tabs. The
Kubernetes sidebar entry gets one child page, "Node pools for each option",
in line with the one-entry-with-children rule for DevOps docs. The existing
runtime pages (`firecracker-sandbox.mdx` and the others) link to it.

**PRs, in order.** (1) the feature table in `pkg/models` and `GET
/v1/runtimes`; (2) `runtimes.list()` in all five SDKs (`/add-sdk-method`),
the MCP tool and `aerolvm get runtimes`; (3) the create error and the
`backend` and `warm` fields; (4) the operator report (preflight, `aerolvm
k8s verify`, chart notes, node listing); (5) the docs page, the Kubernetes
child page and `EVIDENCE.md`. PRs 1 and 5 can ship before M2 for today's
runtimes; PRs 2–4 land with M2 (b), when a second Firecracker option
appears.

## Sources

AWS (read 2026-11-19):

- [What's New: Nitro Sandboxes for EKS, ECS and EC2](https://aws.amazon.com/about-aws/whats-new/2026/11/nitro-sandboxes-eks-ecs-ec2/)
- [EC2: Nitro Sandboxes](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nitro-sandboxes.html), [running Firecracker](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-sandboxes-run-firecracker.html), [attestation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-sandboxes-attestation.html), [NUMA](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-sandboxes-numa.html)
- [EKS: sandboxing](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing.html), [security model](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-security-model.html), [limitations](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-limitations.html), [network isolation](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-network-isolation.html), [metadata and credentials](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-metadata-credentials.html), [storage](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-storage.html), [confidential setup](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing-confidential-setup.html)
- [AWS sample: warm pool](https://aws-samples.github.io/sample-eks-nitro-sandbox/getting-started/warm-pool/)
- [EC2: NitroTPM attestation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html), [attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html), [validating a document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html)

Firecracker (GitHub, `main`, read 2026-11-19):

- [CHANGELOG](https://github.com/firecracker-microvm/firecracker/blob/main/CHANGELOG.md)
- [Nitro Sandboxes: getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/nitro-sandboxes/getting-started.md), [features](https://github.com/firecracker-microvm/firecracker/blob/main/docs/nitro-sandboxes/features.md), [comparison with KVM](https://github.com/firecracker-microvm/firecracker/blob/main/docs/nitro-sandboxes/comparison-with-kvm.md)

AerolVM:

- `plans/kubernetes-v2-architecture.md`: §8.2, §8.6, §8.7, §15, §18 (N2, N7, Phase 0 and Phase 5 results), §20
- `charts/aerolvm/EVIDENCE.md`, `charts/aerolvm/templates/_workerpod.tpl`
- `TODOS.md`: "Design a pod mode for banks that refuse privileged pods"
- The code anchors in sections 2.4 and 3.1

---

## Eng review (2026-11-19)

Target: `plans/security-gaps-m1-m4.md` (this file), branch
`plans/security-gaps-m1-m4`, base `main` at `eb1149db`. Reviewer:
/plan-eng-review (Claude). Context used: the Kubernetes v2 CEO plan
(2026-11-10, owner answer D2) and the code at `eb1149db`.

### Scope record

feature answers: none proposed (the plan is an umbrella for four items; no
cut recommended); structure: A, Smaller arrangement (D3, 2026-11-19);
accepted scope: the plan as written, with the root helper and the gated
containerd API served by one gRPC server on one socket; pending remedies:
R1–R8 below.

### Scope Challenge

Result: **scope accepted as-is** (the D3 change keeps every feature).

- **What already exists.** `HostManager` (`internal/network/netns/host.go:20`)
  is the network boundary. The egress gateway's peer check
  (`internal/egress/peercred_linux.go`) and drop-to-uid pattern are the
  model for the helper socket. `pkg/isolate/shim_linux.go` already does the
  uid drop, no-new-privs and seccomp that Q1 needs for WASM. `aerolvm-supervisor`
  is already root PID 1 in the `runtime` container. Prior art outside the
  repo: Kata Confidential Containers' agent policy denies every
  `CreateContainer` call unless a rule allows it, and a 2026 advisory
  (CVE-2026-77176) came from mount rules that checked the destination but not
  the source. containerd's own threat model treats socket access as root and
  puts all filtering in front of containerd. [Layer 1]
- **Complexity.** About 40+ changed files; 5 new services or processes (root
  helper with the gated containerd API, `internal/rootpolicy`, the `kubepod`
  driver, `aerolvm-guest-init`, the server-side attestation checker). The
  complexity gate ran (D3).
- **TODOS cross-reference.** `TODOS.md:796` (pod mode, P2, trigger: a bank
  refuses privileged pods and S9 fails) is M4. Nothing in `TODOS.md` blocks
  M1–M3.
- **Distribution.** New artifacts: the helper binary (runtime image on
  Kubernetes; `install.sh`, Ansible and Terraform on VMs), a Nitro guest
  kernel (new CI job, correction C1), the guest init (M3). Covered by the
  plan's PR lists after C1.

Factual corrections, applied to the plan text above (no behavior change, so
no question):

- **C1.** `[INFORMATIONAL] (confidence: 10/10) scripts/install.sh:265-272` —
  the plan said "Our kernel build". AerolVM builds no guest kernel; it pins
  Firecracker CI's v1.15 `vmlinux` 5.10.245 by SHA-256
  (`FIRECRACKER_KERNEL_CI_VERSION="v1.15"`). §4.3 now lists a new CI kernel
  build as M2 (b) work.
- **C2.** `[INFORMATIONAL] (confidence: 9/10) internal/network/netns/pool.go:138` —
  the plan named a `ProvisionSandboxNet(id)` call with a path of
  `/run/netns/<id>`. Namespaces belong to pool slots, and `Slot.netnsName`
  reads the name from a recorded path, a sandbox ID or a slot ID. §3.3 now
  uses the existing `HostManager` calls; pool bookkeeping stays in the agent's
  store, and the helper builds the path from a validated ID itself.

Reality rows:

| Premise | Claim | Receipt | Verdict |
|---|---|---|---|
| P1 | Nitro VMs come from upstream Firecracker v1.18 via `PUT /enclave` | Firecracker `CHANGELOG.md`, `docs/nitro-sandboxes/features.md` | true (docs) |
| P2 | Nitro VMs cannot snapshot or pause | EC2 guide, Nitro Sandboxes, "Lifecycle" | true (docs) |
| P3 | Nested virtualization and Nitro Enclaves cannot share an instance | EC2 guide, Nitro Sandboxes | true (docs) |
| P4 | We pin Firecracker v1.15.1 | `packaging/images/versions.env:35` | true |
| P5 | Firecracker Stop/Start always use snapshots | `internal/runtime/firecracker/driver.go` `Stop` → `stopToSandboxSnapshot` | true (subagent read) |
| P6 | WASM workers run as root with only an env allowlist | `pkg/wasm/worker/supervisor.go:31-45` | true |
| P7 | Mount `extra_args`/`opts` reach root tools; only credential words refused | `pkg/models/mounts.go:414-447` | true |
| P8 | AerolVM builds its own guest kernel | `scripts/install.sh:265-272` | **false** (C1) |
| P9 | Netns path is `/run/netns/<sandbox id>` | `internal/network/netns/pool.go:138` | **false** (C2) |
| P10 | Root helper code "changes rarely" | `git log --since=2026-10-20`: netrules 15, netns 9, mounts 10, supervisor 9 commits | **false** (R1) |
| P11 | The guest can call KMS with no AWS credentials of its own | KMS requests need SigV4 credentials | **gap** (R4) |
| P12 | The parent can use the Nitro memory pool while it is idle | none | unverified (SP-B step 5) |
| P13 | M1 adds ≤1 ms warm / ≤3 ms cold | none | unverified (budget) |
| P14 | Karpenter `EC2NodeClass` sets nested virtualization | `plans/kubernetes-v2-architecture.md:686` | unverified (cited, not re-read at source) |
| P15 | The jailer works unchanged with Nitro | Firecracker `docs/nitro-sandboxes/features.md` (Jailer) | true (docs); SP-B confirms |

unverified=3

REALITY: premise-table finding 3 false premises (C1, C2, R1), 1 gap (R4), unverified=3 scripts/install.sh:265
REALITY: already-done pass no branch, PR or TODO builds N2, Nitro or pod mode; pod mode is design-only TODOS.md:796
REALITY: surface-check pass existing settings named in the plan exist (SB_FIRECRACKER_SNAPSHOT_ENABLED and the others, grep of internal/config/config.go); SB_FIRECRACKER_BACKEND is marked new internal/config/config.go:2807
REALITY: binding-decisions pass no branch decisions logged; K4, K5 and CE3 from the K8s v2 CEO plan hold; pod mode's trigger stays an owner decision (§10 item 4) TODOS.md:811
REALITY: numbers finding sizes, PR counts and live costs are [estimated]; boot budget [re-measure before gate]; measured numbers each carry a receipt: cold create 232 ms p50 [measured: plans/kubernetes-v2-architecture.md:1943]; warm create 19 ms p50 [measured: plans/kubernetes-v2-architecture.md:1917]; 1,000 sandboxes per machine [measured: plans/kubernetes-v2-architecture.md:1787]; bare Firecracker boot 817-862 ms [measured: plans/kubernetes-v2-architecture.md:1886]; Phase 0 live cost $8.70 [measured: plans/kubernetes-v2-architecture.md:2047]
REALITY: deferred-asks pass no linked issue; the owner asked for M1-M4 and all four are planned plans/security-gaps-m1-m4.md:53
REALITY: pr-count finding no .gstack/ship-policy.json (default one PR per wave); M1 alone is 12 stacked PRs plus 4 quick wins; per the owner's stacked-PR rule each stack merges as a unit, so each extra PR costs one review and CI cycle, not a separate release plans/security-gaps-m1-m4.md:384

### Section 1: Architecture

**Two shapes (design-twice).** The plan adds new boundaries (the root
helper, the gate), so a second shape is recorded.

- Shape A (the plan): the agent keeps the driver logic and talks to
  containerd through a gate that passes reads and checks writes; the helper
  does typed root work.
- Shape B: the helper owns container lifecycle behind a small typed API
  (`CreateSandboxContainer(spec)`, `Start`, `Kill`, `Delete`, `Exec`,
  `Checkpoint`, `PullImage`) and builds the OCI spec itself; the agent never
  speaks containerd.
- Pick: **A.** B hides more behind a smaller interface, but it puts the spec
  builder into the root image, and the spec builder changes constantly:
  `internal/runtime/containerd/lifecycle.go` had 35 commits in the last 30
  days, while the rules it must obey (`security.go`) had 0. A keeps the
  churning code unprivileged and the stable rules in root.
- Red flags on A: (1) **shallow module**: the gate exposes containerd's
  whole API; fixed by R3 (deny by default, a per-method table). (2)
  **information leakage**: `internal/rootpolicy` is shared by the agent's
  builder and the gate on purpose, so the two cannot drift; kept. (8)
  **hand-synced list**: the gate's method table versus containerd's protos;
  fixed by R3's exhaustiveness test, which fails the build when containerd
  adds a method. Flags 3–7: none found.

Findings, most severe first:

- **R1** `[CRITICAL] (confidence: 8/10) plans/security-gaps-m1-m4.md` §3.3
  "Upgrades" — "The helper sits in the `runtime` image on Kubernetes.
  Changing that image restarts the container and loses its sandboxes ...
  This is why the helper must stay small and its rules stable." The code the
  helper absorbs is not stable: in 30 days `pkg/docker/netrules` had 15
  commits, `internal/network/netns` 9, `pkg/mounts` 10, `internal/supervisor` 9.
  As planned, most releases would need every worker decommissioned, which
  breaks the in-place agent upgrade (S2) the Kubernetes plan rests on.
- **R2** `[CRITICAL] (confidence: 8/10)` §3.3, §3.5 PR 11 — M1 changes the
  worker pod spec (the agent's security context, volumes, shared process
  namespace). Kubernetes applies only image changes in place, so the first
  M1 rollout replaces every worker pod. And an agent built for the split
  cannot run on a pod whose runtime image has no helper. The plan has no
  rollout or version-skew rule for M1 itself.
- **R3** `[CRITICAL] (confidence: 7/10)` §3.3 "The containerd gate" — the
  checked list misses root-equivalent fields: runc options other than
  `BinaryName` (`CriuPath`, `Root`, `ShimCgroup`), the runsc shim's
  `ConfigPath` (a runsc TOML can turn on host networking), checkpoint and
  restore image paths in `Tasks.Create` and `Tasks.Checkpoint`, rootfs mount
  *sources*, namespace default labels, and containerd 2's sandbox API. The
  Kata advisory above failed on exactly the mount-source case.
- **R4** `[INFORMATIONAL] (confidence: 8/10)` §5.2 point 4 — "The guest asks
  KMS itself, over TLS". KMS needs signed requests from some IAM principal,
  and the plan never says whose credentials the guest uses or which principal
  the key policy names for `Decrypt`.
- **R5** `[INFORMATIONAL] (confidence: 7/10)` §6.2 — the pod-mode toolbox
  token would sit in the pod spec (etcd, readable by anyone who can read pods
  in that namespace) and lets its holder run commands in the sandbox.
- **R9** `[INFORMATIONAL] (confidence: 9/10)` §3.3 "What stays out" — the plan
  never says what a broken agent still controls after M1: every sandbox on
  its node (toolbox tokens), their decrypted env (the node cipher) and the
  node's cluster certificate. M1 stops the jump to machine root, the kubelet's
  credentials and the instance role; it does not stop a node-wide tenant
  breach. Correction, no behavior change: recorded in R9 below and in §3.3.

## Decision ledger

### R1: How root-helper code reaches a running worker
Finding: R1, CRITICAL, confidence 8/10, plans/security-gaps-m1-m4.md §3.3 "Upgrades", reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: the helper ships in the `runtime` image; a helper change ships with a runtime image change, which needs a decommission of each worker (§3.3, §7)
Runtime evidence: git log since 2026-10-20: pkg/docker/netrules 15 commits, internal/network/netns 9, pkg/mounts 10, internal/supervisor 9; a runtime container restart loses its sandboxes (plans/kubernetes-v2-architecture.md §8.6)
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1 how helper code reaches a running worker | in the `runtime` image; drain per change | a separate signed helper binary, staged by the agent, run by the supervisor after a signature and version check; hot swap, no drain | in the `runtime` image, but the helper only checks (rule grammar, CNI config); rendering moves to the agent | in the `runtime` image; drain per change |
| R1 rollback rule | none | refuse a helper older than the running one | n/a | n/a |
| R2 M1 rollout and skew | pending | pending | pending | pending |
| R3 gate contract | pending | pending | pending | pending |
Question D4:
D4 — How should root-helper updates reach running workers?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 root helper.
ELI10: The plan puts the new root helper inside the `runtime` container image, and changing that image restarts the container, which kills every sandbox on the worker. The plan assumes the helper rarely changes, but the code it takes over changed 9 to 15 times in the last 30 days. So most releases would mean moving every sandbox off every worker first.
Stakes if we pick wrong: every AerolVM release turns into a full fleet drain, and the "upgrade without touching sandboxes" promise is gone.
Recommendation: A because the supervisor stays tiny and fixed, while the helper upgrades with each release like the agent does, and only a release-signed binary can ever run as root.
Completeness: A=9/10, B=7/10, C=4/10
Pros / cons:
A) Signed hot-swap (recommended)
  ✅ Helper fixes ship every release with no drain; sandboxes never notice a helper restart
  ✅ The agent can stage a file but cannot make root run it without the release signature
  ❌ Adds signature checking and a release signing key to manage (human: ~1 week / CC: ~1 day)
B) Validators-only helper
  ✅ No new key; the root image holds only checkers, which change less than the logic
  ✅ Rendering nft rules and CNI config moves to the unprivileged agent
  ❌ An nft rule checker is hard to get right, and rule changes still drain (human: ~3 weeks / CC: ~4 days)
C) Keep as planned
  ✅ No new work; the simplest design to explain to a bank reviewer
  ❌ Most releases need every worker decommissioned first (minutes per node, recreates for some runtimes)
Net: a small signing system now versus a fleet drain on most releases.
Header: Helper upgrades
Options:
A) Signed hot-swap (recommended)
The supervisor stays tiny and lives in the runtime image. It runs the root helper as a child process from a binary the agent stages each release, only after checking its signature against a release key built into the runtime image and refusing any version older than the one running. Helper restarts never stop sandboxes. Effort human ~1 week / CC ~1 day; risk: signature code runs as root; upkeep: one release key.
B) Validators-only helper
Keep the helper in the runtime image but strip it to checkers: the agent renders nft rules, CNI config and mount argv, and the helper only checks them against fixed rules before applying. Fewer root changes, but a rule-grammar change still needs a drain. Effort human ~3 weeks / CC ~4 days; risk: a weak checker is a root hole.
C) Keep as planned
Leave the helper in the runtime image and decommission every worker whenever helper code changes. No new work; most releases become fleet drains.

State: approved
Actual answer: A) Signed hot-swap (recommended), owner answer to D4, 2026-11-19
Accepted scope: the supervisor stays tiny and fixed in the runtime image and runs the root helper as a child process; each release's agent image carries the helper binary and signature, which the agent stages in a shared folder; the supervisor runs it only after the signature checks against a release public key built into the runtime image and only if its version is not older than the one running; helper restarts never stop sandboxes; VMs run the same signed helper through aerolvm-rootd.service and the node upgrade path checks the same signature; tests: unsigned, wrongly signed, truncated and older binaries are refused, and a helper restart under load keeps every sandbox running
History: none

### R2: How M1 itself rolls out, and agent/helper version skew
Finding: R2, CRITICAL, confidence 8/10, plans/security-gaps-m1-m4.md §3.3 "Upgrades" and §3.5 PR 11, reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: no rollout rule for the switch itself; "Agent N must work with helper N−1" only covers later releases
Runtime evidence: Kubernetes applies only container image changes to a running pod; the M1 chart change (agent securityContext, volumes, shareProcessNamespace) needs a new pod; the operator never restamps running pods (prior learning chart-setting-new-pods-only, 2026-11-16); in-place agent image upgrades are the normal release path (plans/kubernetes-v2-architecture.md §8.2, S2)
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1 helper upgrade path | approved: signed hot-swap (D4) | signed hot-swap (unchanged) | signed hot-swap (unchanged) | signed hot-swap (unchanged) |
| R2 agent behavior with no helper socket | unspecified | falls back to today's in-process root mode, for at least one release after the chart flips | refuses to start | unspecified |
| R2 switch-over of existing workers | unspecified | operator replaces worker pods node by node through decommission; new pods get the split template | upgrade guide says drain every worker at once | unspecified, left to PR 11 |
| R3 gate contract | pending | pending | pending | pending |
Question D5:
D5 — How does M1 itself roll out to workers that already run?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 rollout.
ELI10: Normal releases swap only the agent's image, and the sandboxes keep running. M1 is different: it changes the worker pod's settings (the agent stops being privileged), and Kubernetes can only apply that by making new pods. Meanwhile an agent built for M1 might get swapped onto an old pod that has no helper. The plan says nothing about either case.
Stakes if we pick wrong: the first upgrade that carries M1 crash-loops agents on old pods, or forces one big drain of the whole fleet.
Recommendation: A because a dual-mode agent keeps the normal in-place upgrade safe, and node-by-node replacement is the decommission path the operator already has.
Completeness: A=9/10, B=6/10, C=3/10
Pros / cons:
A) Dual-mode, node by node (recommended)
  ✅ An in-place agent upgrade onto an old pod keeps working, so the normal release path never breaks
  ✅ Workers switch one at a time through the decommission the operator already runs
  ❌ Two agent modes to test for at least one release (human: ~3 days / CC: ~4 hours)
B) Hard cutover
  ✅ One agent mode only; less code and a simpler test matrix
  ✅ The fleet is fully on the split after a single upgrade window
  ❌ Agents crash-loop on any old pod, and the upgrade needs a drain of every worker at once
C) Leave it to PR 11
  ✅ No plan change now; the chart PR decides when it is written
  ❌ The riskiest step of M1 gets designed last, under release pressure
Net: one release of dual-mode code versus a fleet-wide drain or a crash loop.
Header: M1 rollout
Options:
A) Dual-mode, node by node (recommended)
The agent checks for the helper socket at start. Found: split mode. Not found: today's in-process root mode, which works only because the old pod is still privileged. Keep both modes for at least one release after the chart flips. The operator moves each worker to the new pod template through its decommission path, node by node. Tests cover both modes and a mixed fleet. Effort human ~3 days / CC ~4 hours.
B) Hard cutover
Release N needs the new pod template. The agent refuses to start without the helper, and the upgrade guide says to drain every worker. Simpler code; one big drain, and agents crash-loop on any pod still on the old template.
C) Leave it to PR 11
Keep the plan as written and let the chart PR choose the rollout when it is written. No plan change now; the riskiest step is designed last.

State: approved
Actual answer: A) Dual-mode, node by node (recommended), owner answer to D5, 2026-11-19
Accepted scope: the agent checks for the helper socket at start and runs split mode when it is found, today's in-process root mode when it is not (possible only on a still-privileged old pod); both modes stay for at least one release after the chart flips; the operator moves each worker to the new pod template node by node through its decommission path; tests cover both modes and a mixed fleet; plan §3.3 "Upgrades" and §3.5 PR 11 amended
History: extended on 2026-11-20 by D22: the dual mode becomes a lasting setting privilegeMode: split | single; new installs default to split; existing installs keep their current mode on upgrade until the operator switches

### R3: The containerd gate's contract
Finding: R3, CRITICAL, confidence 7/10, plans/security-gaps-m1-m4.md §3.3 "The containerd gate", reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: reads pass; `Containers.Create`/`Update`, `Tasks.Create`, `Tasks.Exec` checked against the security.go envelope; runtime options checked for `BinaryName` only; "allow by name and refuse the rest" stated in Risks but no method list
Runtime evidence: containerd's threat model: socket access is root, and containerd fulfils whatever privilege the client asks for; Kata CoCo CVE-2026-77176: a policy checked a mount's destination but not its source; gRPC-Go path-based authz bypass when a deny list sits over a default allow. Root-equivalent fields the plan's list misses: runc options `CriuPath`, `Root`, `ShimCgroup`; the runsc shim's `ConfigPath`; checkpoint/restore image paths (`Tasks.Create`, `Tasks.Checkpoint`); rootfs mount sources; `Diff.Apply` mounts (client-supplied target mounts that containerd writes into as root); namespace default labels; containerd 2's sandbox API
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1 helper upgrade path | approved: signed hot-swap (D4) | unchanged | unchanged | unchanged |
| R2 M1 rollout | approved: dual-mode, node by node (D5) | unchanged | unchanged | unchanged |
| R3 which containerd methods pass | unstated ("allow by name") | only the methods the agent calls today; every other method refused | every containerd method gets a row: pass, check or refuse | unstated, PR 3 decides |
| R3 fields checked on allowed writes | OCI spec rules + `BinaryName` | OCI spec rules + all runtime options (`BinaryName`, `CriuPath`, `Root`, `ShimCgroup`, runsc `ConfigPath`), checkpoint/restore paths, rootfs and `Diff.Apply` mount types and sources, namespace labels; sandbox API refused | same field list | OCI spec rules + `BinaryName` |
| R3 new fields after a containerd bump | unhandled | a test pins each allowed message's fields; a new field fails the build, and an unknown non-empty field is refused at run time | a test fails when containerd adds a method or field | unhandled |
| R6 refusal alerting | pending | pending | pending | pending |
Question D6:
D6 — Which containerd calls may the agent make through the gate?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 containerd gate.
ELI10: The gate is the wall between the unprivileged agent and containerd, which can do anything as root. The plan checks the container spec, but containerd has other fields that also mean root: which program the shim runs, where checkpoints are read from, which host folders get mounted, a gVisor config file path. A known Kata bug came from checking where a mount goes but not where it comes from. The gate needs an exact list.
Stakes if we pick wrong: one unchecked field lets a broken agent get root, and M1 then proves nothing to a bank.
Recommendation: A because the agent uses a small, known set of calls, so refusing everything else is the smallest surface, and a field-pin test catches containerd upgrades that add fields.
Completeness: A=9/10, B=8/10, C=4/10
Pros / cons:
A) Allowlist used calls (recommended)
  ✅ Only the calls AerolVM makes today get through; containerd's other APIs are refused outright
  ✅ A containerd bump that adds a field to an allowed call fails the build before it ships
  ❌ A new feature that needs a new containerd call needs a helper change (cheap after D4) (human: ~1 week / CC: ~1 day)
B) Table for every method
  ✅ Every containerd method has a written decision a bank reviewer can read
  ✅ Unused but harmless reads keep working for debugging tools
  ❌ Many more methods to reason about and keep right on each containerd bump (human: ~2 weeks / CC: ~2 days)
C) Leave it to PR 3
  ✅ No plan change now; PR 3 works it out against the code
  ❌ The plan's security claim rests on a list nobody has written yet
Net: the smallest allowlist with a build-time tripwire versus a full table or no list yet.
Header: Gate contract
Options:
A) Allowlist used calls (recommended)
The gate passes only the containerd methods the agent calls today (PR 3 derives the list from internal/runtime/containerd) and refuses all others, including the sandbox API. On allowed writes it checks the OCI spec rules plus every runtime option (BinaryName, CriuPath, Root, ShimCgroup, runsc ConfigPath), checkpoint and restore paths, the type and source of rootfs and Diff.Apply mounts, and namespace labels. A test pins each allowed message's fields so a containerd bump that adds one fails the build; unknown non-empty fields are refused at run time. Effort human ~1 week / CC ~1 day.
B) Table for every method
Write a pass, check or refuse row for every containerd method, with the same field checks, and a test that fails when containerd adds a method or field. More to maintain on every containerd bump. Effort human ~2 weeks / CC ~2 days.
C) Leave it to PR 3
Keep the plan's current list (spec rules and BinaryName) and let PR 3 work out the rest. No plan change now.

State: approved
Actual answer: A) Allowlist used calls (recommended), owner answer to D6, 2026-11-19
Accepted scope: the gate passes only the containerd methods the agent calls today (PR 3 derives the list from internal/runtime/containerd) and refuses all others, including the sandbox API and namespace writes; allowed writes check the OCI spec rules plus BinaryName, CriuPath, Root, ShimCgroup and runsc ConfigPath, checkpoint and restore paths, the type and source of rootfs and Diff.Apply mounts, and namespace labels; a test pins each allowed message's fields so a containerd bump that adds one fails the build; unknown non-empty fields are refused at run time; plan §3.3 "The containerd gate" amended
History: none

### R4: Whose AWS identity the confidential guest uses to call KMS
Finding: R4, INFORMATIONAL, confidence 8/10, plans/security-gaps-m1-m4.md §5.2 point 4 ("The guest asks KMS itself, over TLS"), reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: the key policy lets servers wrap and allows Decrypt only with RecipientAttestation conditions; the caller's credentials and the Decrypt principal are not named
Runtime evidence: KMS accepts only SigV4-signed requests from an IAM principal; the AWS attestation docs show KMS returning CiphertextForRecipient (encrypted to the key in the attestation document), so the caller's credentials alone open nothing; AerolVM already mints per-sandbox OIDC tokens (internal/cloudidentity/doc.go)
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1 / R2 / R3 | approved (D4, D5, D6) | unchanged | unchanged | unchanged |
| R4 credentials the guest signs KMS calls with | unnamed | short-lived credentials of the worker's instance role, passed to the guest over vsock | the sandbox's own OIDC token (minted by the server, encrypted to the guest), swapped for the customer's role with AssumeRoleWithWebIdentity | unnamed |
| R4 Decrypt principal in the key policy | unnamed | the worker node role, and only with the RecipientAttestation conditions; a Deny on any Decrypt without an attestation document | the customer's per-team role, with the same conditions and Deny | unnamed |
| R4 CloudTrail attribution of each release | none | per worker node | per sandbox | none |
| R5 pod-mode toolbox token | pending | pending | pending | pending |
Question D7:
D7 — Whose AWS identity does a confidential guest use to call KMS?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M3 secret release.
ELI10: In the confidential tier, the guest asks AWS KMS to unlock its secrets and proves what it runs with an attestation document. But KMS only answers calls signed with some AWS identity, and the plan never says whose. The answer is encrypted to a key only the guest holds, so the signing identity cannot read it either way. The choice is about setup work and audit trail.
Stakes if we pick wrong: M3 v1 cannot be built as written, or customers face IAM setup that blocks adoption.
Recommendation: A because it is AWS's standard Nitro pattern, needs no per-customer IAM trust setup, and stays safe since KMS encrypts its answer to the guest's attested key.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Worker node role (recommended)
  ✅ AWS's own Nitro Enclaves pattern; works with no customer IAM setup beyond the key policy
  ✅ A stolen node credential opens nothing: the answer is encrypted to the guest's own key
  ❌ CloudTrail shows the worker node, not the sandbox, as the caller (human: ~2 days / CC: ~3 hours)
B) Sandbox's own OIDC role
  ✅ CloudTrail names each sandbox's team role on every release; per-team key policies
  ✅ Reuses the per-sandbox OIDC tokens AerolVM already mints
  ❌ Each customer must set up an IAM trust for AerolVM's issuer first (human: ~4 days / CC: ~6 hours)
C) Leave it to the M3 PRs
  ✅ No plan change now; M3 starts only after M2 (b), months away
  ✅ The M3 PRs could try both identities against a real KMS key first
  ❌ M3 v1's key policy example, docs and tests have no principal to name
Net: zero customer IAM setup versus per-sandbox CloudTrail attribution.
Header: KMS identity
Options:
A) Worker node role (recommended)
The worker passes short-lived credentials of its instance role to the guest over vsock. The key policy allows Decrypt for that role only with the RecipientAttestation conditions (PCR0 image hash and the allowed PCR17 profiles), and a Deny refuses any Decrypt that carries no attestation document. CloudTrail shows the node as caller. Effort human ~2 days / CC ~3 hours.
B) Sandbox's own OIDC role
The server mints the sandbox's OIDC token and encrypts it to the guest's attested key; the guest swaps it for the customer's team role with AssumeRoleWithWebIdentity and calls KMS with the same conditions and Deny. CloudTrail names the team role. Each customer must trust AerolVM's issuer first. Effort human ~4 days / CC ~6 hours.
C) Leave it to the M3 PRs
Keep §5.2 as written and let the M3 PRs pick the caller and principal.

State: approved
Actual answer: B) Sandbox's own OIDC role, owner answer to D7, 2026-11-19 (against the recommendation of A)
Accepted scope: the server mints the sandbox's OIDC token and encrypts it to the guest's attested key; the guest swaps it for the customer's team role with AssumeRoleWithWebIdentity and calls KMS Decrypt; the key policy names that team role as the only Decrypt principal, with the RecipientAttestation conditions and a Deny on any Decrypt without an attestation document; CloudTrail names the team role; the confidential tier requires per-sandbox cloud identity and an IAM trust for AerolVM's issuer, documented on the M3 docs page; plan §5.2 point 4 amended
History: none

### R5: How a pod-mode sandbox's toolbox trusts its worker
Finding: R5, INFORMATIONAL, confidence 7/10, plans/security-gaps-m1-m4.md §6.2 ("Env: never in the pod spec ... the worker pushes env over mTLS with the toolbox token"), reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: env stays out of the pod spec; the toolbox token's own path is unstated, so it would ride the pod spec or its env like today's create arguments
Runtime evidence: `runtime.Runtime.Create` takes a `toolboxToken` argument (internal/runtime/runtime.go:54); anything in a pod spec is stored in etcd and readable by anyone with `get pods` in that namespace; the cluster already issues worker certificates carrying `node:<id>` (plans/kubernetes-v2-architecture.md §15.2)
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R4 | approved (D4–D7) | unchanged | unchanged | unchanged |
| R5 how toolboxd knows a caller is its worker | toolbox token, path unstated (pod spec) | mTLS: toolboxd trusts the cell's worker CA (public cert in a ConfigMap) and only the worker named in its pod spec (a node ID, not a secret); the worker pushes the toolbox token with env in that first mTLS call | the token in a per-pod Kubernetes Secret, mounted into the pod | the token in the pod spec |
| R5 secret material stored in etcd per sandbox | the token | none | the token, in a Secret (encrypted at rest only if the cluster turns that on) | the token |
| R5 Kubernetes writes per cold create | 2 (pod create and delete) | 2 | 4 (pod and Secret, create and delete) | 2 |
Question D8:
D8 — How should a pod-mode sandbox know a call comes from its own worker?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M4 pod mode.
ELI10: In pod mode each sandbox is a Kubernetes pod with AerolVM's toolbox inside. Today the toolbox trusts a token. If that token sits in the pod's spec, anyone allowed to read pods in that namespace can copy it and run commands in the sandbox. The plan keeps env out of the spec but forgot the token.
Stakes if we pick wrong: a person or tool with read-only pod access can run code inside customers' sandboxes.
Recommendation: A because the worker already holds a cluster certificate, so the toolbox can check the caller with mTLS and nothing secret ever reaches etcd.
Completeness: A=9/10, B=6/10, C=3/10
Pros / cons:
A) Worker mTLS, no token (recommended)
  ✅ Nothing secret is stored in etcd; read access to pods reveals no credential
  ✅ Reuses the worker certificates the cluster already issues and renews
  ❌ toolboxd gains a client-certificate check and a CA bundle to load (human: ~3 days / CC: ~4 hours)
B) Token in a Secret
  ✅ Small change: Kubernetes mounts the Secret and toolboxd reads a file
  ✅ Secrets have their own RBAC, separate from pod read access
  ❌ The token still lives in etcd and doubles the Kubernetes writes per cold create
C) Keep as planned
  ✅ No new code in toolboxd or the driver
  ✅ The token reaches the toolbox the same way as on the other engines today
  ❌ Anyone who can read pods in that namespace can run commands in the sandbox
Net: a client-certificate check versus a credential stored in etcd.
Header: Pod-mode trust
Options:
A) Worker mTLS, no token (recommended)
toolboxd in a pod-mode sandbox trusts only the cell's worker CA (a public certificate in a ConfigMap) and only the worker named in its pod spec (a node ID, not a secret). The worker pushes the toolbox token together with env in that first mTLS call. Nothing secret reaches etcd; cold creates stay at 2 Kubernetes writes. Effort human ~3 days / CC ~4 hours.
B) Token in a Secret
Store the toolbox token in a per-pod Kubernetes Secret mounted into the pod. Separate RBAC from pod reads, but the token is in etcd and each cold create writes 4 objects instead of 2.
C) Keep as planned
Leave the token in the pod spec as today's create arguments would put it. No new code; anyone with pod read access in that namespace can use it.

State: approved
Actual answer: A) Worker mTLS, no token (recommended), owner answer to D8, 2026-11-19
Accepted scope: toolboxd in a pod-mode sandbox trusts only the cell's worker CA (public certificate in a ConfigMap) and only the worker named in its pod spec (a node ID); the worker pushes the toolbox token and env together in that first mTLS call; nothing secret reaches etcd; cold creates stay at 2 Kubernetes writes; plan §6.2 amended
History: none

### R9: What a broken agent still controls (correction)
Finding: R9, INFORMATIONAL, confidence 9/10, plans/security-gaps-m1-m4.md §3.3 "What stays out", reviewer /plan-eng-review (Claude)
Plan baseline: original proposal said nothing about the agent's own reach after M1
Runtime evidence: the agent holds each sandbox's toolbox token (`runtime.Runtime.Create`, internal/runtime/runtime.go:54), the node cipher that opens env (`Service.loadEnv`, internal/service/service.go:3615) and the node's cluster certificate (plans/kubernetes-v2-architecture.md §15.2)
Correction: no behavior change, so no question. §3.3 now says a broken agent still reaches every sandbox on its node and its secrets; M1 stops the step to machine root, the kubelet's credentials, the instance role and the kernel; per-team worker pools (N6) limit a breach to one team.
State: approved (correction)
Actual answer: none needed (factual correction)
Accepted scope: plan §3.3 text only
History: none

### D4 carried work: helper swap with calls in flight
Necessary implementation of approved R1 (D4), no new question: during a hot swap the old helper stops accepting and finishes its calls in flight before the new helper accepts on the same listening socket (exclusive handover, corrected by outside review O6 so D11's per-sandbox order holds across the swap); the supervisor verifies and runs a root-owned copy of the staged binary, never the staged path (outside review O3); the agent retries calls whose connection dropped (all idempotent). Tests: a swap during 100 parallel creates loses no create and stops no sandbox; a Remove then Realize for one sandbox straddling a swap ends realized; replacing the staged file after the check never changes what runs. Plan §3.3 "Upgrades" amended.
History: first version let the old and new helper overlap; corrected after outside review O6 (2026-11-19).

### Section 1 dispositions
R1 accepted (D4, A); R2 accepted (D5, A); R3 accepted (D6, A); R4 accepted (D7, B, against the recommendation); R5 accepted (D8, A); R9 correction applied. C1, C2 corrections applied.

### Section 2: Code quality

- **What exists, reused.** `egress.UnixPeerCheck` (`internal/egress/peercred_linux.go:19`, 54 lines) already has two callers (`internal/egress/gatewayd/run.go:59`, `pkg/daemon/egress_procid_wiring.go:94`); the helper's socket should call it, not copy it. `internal/rootpolicy` has two proven callers: the existing spec builder (`securitySpecOpts`, `internal/runtime/containerd/security.go`) and the proposed gate. No other extraction proposed.
- **Diagrams.** The §3.3 diagram was updated for D3 (one socket). Accurate.
- **R6** `[INFORMATIONAL] (confidence: 7/10)` §3.3 "Failure rules" — a refusal by the gate or the helper means the agent asked for something its own code never builds: drift or a compromise. The plan treats it as a plain error ("A down helper fails a create with a clear `503`"); nothing records or alerts on it.

### R6: What happens when the gate or helper refuses a call
Finding: R6, INFORMATIONAL, confidence 7/10, plans/security-gaps-m1-m4.md §3.3 "Failure rules", reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: refusals return an error; no audit, metric or alert
Runtime evidence: in normal operation the agent only sends requests its own builder made, which the shared rules accept (D6 tests), so a refusal should never happen; the repo already ships Prometheus alert rules with tests (setup/prometheus/sandboxd-alerts.yml, setup/prometheus/alerts_test.go) and a hash-chained audit log
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R5 | approved (D4–D8) | unchanged | unchanged | unchanged |
| R6 refusal recorded in the audit log | no | yes: one event per refusal (call, reason, node) | no | no |
| R6 refusal metric | no | `aerolvm_rootd_refusals_total{call,reason}` | `aerolvm_rootd_refusals_total{call,reason}` and a log line | no |
| R6 alert | no | fires on any refusal in 5 minutes, with a rule test in alerts_test.go | no | no |
| R7 helper concurrency | pending | pending | pending | pending |
Question D9:
D9 — Should a refused root call raise an alarm?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 failure handling.
ELI10: The agent only ever sends requests its own code built, and those always pass the shared rules. So if the gate or the root helper ever says no, either the code drifted or someone broke into the agent and is probing for root. The plan treats that as an ordinary error, so nobody would notice an attack in progress.
Stakes if we pick wrong: an attacker can try root-escalation requests over and over with no alert and no record.
Recommendation: A because a refusal should never happen in normal running, so any refusal is worth a page and an audit record.
Completeness: A=9/10, B=6/10, C=3/10
Pros / cons:
A) Audit, metric and alert (recommended)
  ✅ Every refusal lands in the tamper-evident audit log a bank can review later
  ✅ An alert fires on the first refusal, so probing is seen while it happens
  ❌ A gate bug that refuses a real request pages someone (human: ~1 day / CC: ~1 hour)
B) Metric and log only
  ✅ Dashboards show refusals with no risk of a noisy page
  ✅ Less wiring: no audit event type and no alert rule test
  ❌ No durable record and nobody is told while an attack happens
C) Plain error
  ✅ No new code at all
  ✅ The create still fails safely, so nothing unsafe runs either way
  ❌ An attack in progress looks like a flaky create
Net: an alert and audit record versus a quiet error.
Header: Refusal alerts
Options:
A) Audit, metric and alert (recommended)
Each refusal by the gate or the helper writes an audit event (call, reason, node), counts in aerolvm_rootd_refusals_total{call,reason}, and a new rule in setup/prometheus/sandboxd-alerts.yml fires on any refusal within 5 minutes, tested in alerts_test.go. The create still fails with a 500. Effort human ~1 day / CC ~1 hour.
B) Metric and log only
Count refusals in aerolvm_rootd_refusals_total{call,reason} and log each one. No audit event and no alert.
C) Plain error
Keep the plan: a refusal is an error returned to the caller, with nothing recorded.

State: approved
Actual answer: A) Audit, metric and alert (recommended), owner answer to D9, 2026-11-19
Accepted scope: each refusal by the gate or the helper writes an audit event (call, reason, node), counts in aerolvm_rootd_refusals_total{call,reason}, and a new rule in setup/prometheus/sandboxd-alerts.yml fires on any refusal within 5 minutes, tested in setup/prometheus/alerts_test.go; the create fails with a 500; plan §3.3 "Failure rules" amended
History: none

### Section 2 dispositions
R6 accepted (D9, A). No extraction beyond `internal/rootpolicy`; reuse `egress.UnixPeerCheck` as is.

### Section 3: Tests

Framework: Go `testing`, table-driven, `make test` offline; tag-gated kind
and live AWS suites (CLAUDE.md "Testing & coverage"). Coverage bar 85% per
package. All M1–M4 paths are proposals; the diagram marks what an existing
test already protects and what is a gap.

```
CODE PATHS                                              USER / OPERATOR FLOWS
[+] M1 root helper (proposed)                           [+] Create, exec, files, destroy on the split worker
  ├── socket peer check                                   ├── [GAP] [→E2E] gVisor/runc on kind, agent as uid 65532
  │   └── [★★ reuse] egress.UnixPeerCheck tests           ├── [GAP] [→E2E] WASM, V8, Firecracker on kind
  ├── HostManager Realize/Remove via helper               └── [GAP] [→E2E] one live EKS drill (S2, OV-E2, F8, F10, N1)
  │   └── [★★★ TESTED] netns host_*_test.go (fakes)     [+] Upgrade flows
  ├── firewall calls (typed policy → nft)                 ├── [GAP] [→E2E] in-place agent swap on an old pod (D5 dual mode)
  │   └── [★★★ TESTED] 36 netrules tests (render)         ├── [GAP] [→E2E] node-by-node move to the new template (D5)
  ├── EnsureHostPort (TCP pool, fragile)                  └── [GAP] signed helper hot swap during 100 creates (D4)
  │   └── [★★★ TESTED] store_test.go, layer4_bootstrap  [+] Attack flows ("broken agent" suite, §3.6)
  ├── cgroups / F10 OOM                                   ├── [GAP] privileged spec, hook, bind of /, BinaryName,
  │   └── [★★ TESTED] oom_kernel_test.go                  │        CriuPath, ConfigPath, Diff.Apply source, ../ netns
  ├── mounts (allowlisted opts, FUSE as non-root)         ├── [GAP] unsigned / older helper binary refused (D4)
  │   └── [GAP] allowlist rows; non-root FUSE             └── [GAP] refusal → audit event + alert (D9)
  ├── host processes (WASM uid drop, jailer, workerd)
  │   └── [GAP] Q1 uid/seccomp drop; jailer via helper
  └── containerd gate (D6)
      ├── [★★★ TESTED] security_test.go, security_capdrop_test.go (envelope)
      ├── [GAP] allowlist: unlisted method refused
      ├── [GAP] field pin: new containerd field fails build
      └── [GAP] builder output always passes; each mutation refused
[+] M2 (b) Nitro backend (proposed)
  ├── [GAP] PutEnclave before InstanceStart; no TrackDirtyPages
  ├── [GAP] cold Stop/Start keeps disk, same TAP slot; Pause → 409
  └── [GAP] admission: 5/vCPU, 896/host, 256 MiB, even vCPU on SMT
[+] M3 v1 (proposed)
  ├── [GAP] PCR16/17/18 extend before tenant code
  ├── [GAP] profile refuses host exec/files (toolboxd)
  ├── [GAP] server attestation checker: bad chain, wrong PCR0/17/18/4, stale nonce
  ├── [GAP] OIDC token sealed to attested key (D7); inspect/inject refused (409)
  └── [GAP] [→E2E] live: KMS Decrypt only with a good document
[+] M4 pod mode (proposed)
  ├── [GAP] kubepod Create idempotent on AlreadyExists; informer ListManaged
  ├── [GAP] toolboxd mTLS: only its named worker (D8)
  └── [GAP] [→E2E] kind with gVisor RuntimeClass; EKS Auto Mode isolated-sandbox

COVERAGE (existing protection of behavior M1 moves): 6/14 paths (43%)
QUALITY: ★★★:4 ★★:2  |  GAPS: proposed paths all need new tests (planned in §3.6, §4.3, §5.4, §6.5)
```

Legend: ★★★ behavior + edge + error | ★★ happy path | ★ smoke | [→E2E] needs
integration test. No LLM or prompt code is touched, so no eval scope.

Tests made obsolete by this plan: none. The existing netns, netrules,
cgroup and security tests keep running against the same code, now called
through the helper.

**Regression risk.** M1 moves every privileged path behind a new process
boundary. The behaviors below already work and have tests or live proofs;
M1 puts all of them at risk (IRON RULE).

### R8: The regression contract for M1
Finding: R8, CRITICAL, confidence 9/10, plans/security-gaps-m1-m4.md §3.6, reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: §3.6 lists new tests (broken-agent suite, rootpolicy fuzz, kind proofs, one EKS run) but names no contract for behavior that must not change
Runtime evidence: live proofs and tests that pass today: S2 agent swap and OV-E2 external mount (integration-tests/k8s/s2.sh, s2m.sh); F8 namespace cleanup; F10 OOM (internal/runtime/containerd/oom_kernel_test.go); netns (internal/network/netns/host_*_test.go); 36 netrules test files; TCP host-port pool (internal/store/store_test.go, internal/service/layer4_bootstrap_test.go); envelope (internal/runtime/containerd/security_test.go); Firecracker on kind (integration-tests/k8s/fckind.sh)
Comparison grid:
| Choice | Current | A | B |
|---|---|---|---|
| R1–R6 | approved (D4–D9) | unchanged | unchanged |
| R8 behavior that must not change | unnamed | S2 (sandboxes keep running across an agent swap), OV-E2 (external mount reaches the sandbox and survives the swap), F8 (no leaked namespaces after a pod delete), F10 (memory pressure kills one sandbox, never the machinery), egress rules, node guard, floor, IPv6 fence and metadata block, the TCP host-port pool, WASM/V8/Firecracker create, exec, adoption after an agent restart, gVisor and Firecracker moves, and a VM single-node install and upgrade | same list |
| R8 intended differences | unnamed | the agent runs as uid 65532 with no rights; namespaces are made in the `runtime` container; external storage on by default | same |
| R8 how it is proven | partly (§3.6) | offline tests against a fake helper + every existing kind proof re-run on the split worker + one live EKS drill (S2, OV-E2, F8, F10, the N1 benchmark) before the chart flips | offline tests against a fake helper + every existing kind proof; no live run |
| R8 TCP pool rule (CLAUDE.md non-negotiable 5) | not stated | a regression test in store_test.go / layer4_bootstrap_test.go style for EnsureHostPort via the helper, and a PR call-out | same |
| R7 helper concurrency | pending | pending | pending |
Question D10:
D10 — How deep must M1's regression proof go before the chart flips?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 regression contract.
ELI10: M1 moves every root action (networks, firewall, memory limits, mounts, VM launch) behind a new process. All of that works today and has tests or live proofs: sandboxes survive an agent upgrade, external storage reaches the sandbox, memory pressure kills one sandbox and not the worker, the firewall rules hold. The plan lists new tests but never says these must keep passing. The question is how to prove it: tests and kind only, or also one live EKS run.
Stakes if we pick wrong: an EKS-only failure reaches banks; Phase 0's F1, F2, F8 and F10 showed up only on real EKS nodes.
Recommendation: A because Phase 0's F1, F2, F8 and F10 were found only on real EKS nodes, and one drill costs about $10.
Completeness: A=10/10, B=7/10
Pros / cons:
A) Tests, kind and one EKS drill (recommended)
  ✅ Catches failures that only show on real EKS nodes (AL2023 kernel, VPC CNI, kubelet)
  ✅ The N1 benchmark gives real before/after create latency for the boot-path call-out
  ❌ One live run, about $10 and a few hours (human: ~1 day / CC: ~2 hours plus run time)
B) Tests and kind only
  ✅ Free; runs in CI on every PR of the stack
  ✅ Still re-runs every existing proof on the split worker
  ❌ EKS-only failures stay hidden until a bank finds them
Net: about $10 of live proof versus trusting kind for EKS behavior.
Header: Regression proof
Options:
A) Tests, kind and one EKS drill (recommended)
Behavior that must not change: S2, OV-E2, F8, F10, egress rules and guards, the TCP host-port pool (with its CLAUDE.md regression test and call-out), WASM/V8/Firecracker create, exec and adoption, gVisor and Firecracker moves, VM install and upgrade. Proof: offline tests against a fake helper, every existing kind proof on the split worker, and one live EKS drill (S2, OV-E2, F8, F10, N1) before the chart flips. About $10.
B) Tests and kind only
The same must-not-change list and intended differences, proven with offline tests against a fake helper and every existing kind proof on the split worker. No live EKS run.

State: approved
Actual answer: A) Tests, kind and one EKS drill (recommended), owner answer to D10, 2026-11-19
Accepted scope: must-not-change list S2, OV-E2, F8, F10, egress rules and guards, the TCP host-port pool (regression test in store_test.go / layer4_bootstrap_test.go style and a PR call-out), WASM/V8/Firecracker create, exec and adoption, gVisor and Firecracker moves, VM install and upgrade; intended differences: agent as uid 65532 with no rights, namespaces made in the runtime container, external storage on by default; proof: offline tests against a fake helper, every existing kind proof on the split worker, one live EKS drill (S2, OV-E2, F8, F10, N1) before the chart flips, about $10; plan §3.6 amended
History: none

### Section 3 dispositions
R8 accepted (D10, A). Test plan artifact:
`~/.gstack/projects/aerol-ai-microvm/sumansaurabh-plans-security-gaps-m1-m4-eng-review-test-plan-20261119-114617.md`.

### Section 4: Performance

- **Faster, not slower, on one path.** Today every create mounts the
  image's snapshot to read `/etc/passwd` (`oci.WithImageConfig`,
  `internal/runtime/containerd/lifecycle.go:245`). `ResolveImageUser`
  cached per image digest removes that mount from every create after the
  first of an image. Scale: one fewer overlay mount per create.
- **Gate decode cost.** One OCI spec JSON parse per container create, in
  the tens of microseconds. Scale: creates per worker per second, unknown
  in production; the cell bench ran 1,202 creates/s over 500 workers
  (about 2.4 per worker). Not a concern; the N1 run in D10 measures it.
- **M4 informer.** One namespace informer per pod-mode worker, filtered by
  its label. Scale: the pods that worker owns (hundreds). Not a concern.
- **M3 guest-side image check.** Seconds per cold create for large images;
  already in §9 Risks with the v2 `dm-verity` fix.
- **R7** `[INFORMATIONAL] (confidence: 6/10, medium confidence, verify)` §3.3
  — the plan never says the helper serves calls concurrently. Today the
  same code runs in-process with no global lock: `netns.Host` has none, and
  netrules locks only its block-set connection
  (`pkg/docker/netrules/netlink_backend.go:49`, "commits on a node run one
  at a time in the kernel anyway"). A helper written with one lock around
  every call would turn parallel creates into a queue.

### R7: Whether the root helper must serve calls in parallel
Finding: R7, INFORMATIONAL, confidence 6/10, plans/security-gaps-m1-m4.md §3.3 and §3.7, reviewer /plan-eng-review (Claude)
Plan baseline: original proposal: boot-path budget +1 ms warm / +3 ms cold p50 (§3.7); no concurrency rule for the helper
Runtime evidence: today's in-process code has no global lock (internal/network/netns/host.go `Host` struct; pkg/docker/netrules/netlink_backend.go:49 locks only the block-set connection); gRPC servers handle calls in parallel unless the handler serializes them; the N1 run (D10) includes a burst larger than the warm pool
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R6, R8 | approved (D4–D10) | unchanged | unchanged | unchanged |
| R7 helper concurrency rule | unstated | calls run in parallel; calls for one sandbox run in order (a per-sandbox lock); shared kernel objects keep only the locks they have today | one call at a time | unstated |
| R7 proof | none | a 100-parallel-create benchmark in the PR that wires the first call, p50 and p99 against today's in-process path, inside the §3.7 budget | the N1 run only | the N1 run only |
Question D11:
D11 — Must the root helper handle many creates at once?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 performance.
ELI10: Today the root work for many sandbox creates runs side by side inside the agent. The plan moves it into the helper but never says the helper must keep doing it side by side. If someone writes the helper with one lock around everything, a burst of 100 creates waits in a single line, and create times jump.
Stakes if we pick wrong: bursts of creates slow down on every worker, which is AerolVM's lead over both rivals.
Recommendation: A because today's code already runs in parallel, so writing the rule down and benchmarking it costs little and protects the 232 ms / 19 ms lead.
Completeness: A=9/10, B=6/10, C=4/10
Pros / cons:
A) Parallel, per-sandbox order (recommended)
  ✅ Keeps today's behavior: creates for different sandboxes never wait on each other
  ✅ A 100-create benchmark in the first wiring PR proves it before the chart flips
  ❌ Per-sandbox locks need care around a sandbox's create racing its delete (human: ~2 days / CC: ~3 hours)
B) One call at a time
  ✅ Simplest helper to reason about; no races inside it at all
  ✅ The N1 run would still show how much it costs
  ❌ A create burst queues behind one lock; slower than today on every worker
C) Leave it unstated
  ✅ No plan change now
  ✅ The implementer can pick after seeing real numbers
  ❌ Nothing stops a global lock from slipping in unnoticed until the N1 run
Net: a written concurrency rule plus a benchmark versus finding out late.
Header: Helper concurrency
Options:
A) Parallel, per-sandbox order (recommended)
The helper serves calls in parallel. Calls for one sandbox run in order under a per-sandbox lock. Shared kernel objects keep only the locks they have today. The PR that wires the first call adds a 100-parallel-create benchmark, p50 and p99 against today's in-process path, within the §3.7 budget. Effort human ~2 days / CC ~3 hours.
B) One call at a time
The helper serializes every call behind one lock. Simplest to reason about; the N1 run shows the cost.
C) Leave it unstated
Keep the plan as written; the implementer picks a concurrency model, and only the N1 run would catch a slowdown.

State: approved
Actual answer: A) Parallel, per-sandbox order (recommended), owner answer to D11, 2026-11-19
Accepted scope: the helper serves calls in parallel; calls for one sandbox run in order under a per-sandbox lock; shared kernel objects keep only the locks they have today; the PR that wires the first call adds a 100-parallel-create benchmark, p50 and p99 against today's in-process path, within the §3.7 budget; plan §3.7 amended
History: none

### Section 4 dispositions
R7 accepted (D11, A).

### Outside voice (Codex, gpt-6-astra, completed)

Codex returned 8 findings, `VERDICT: FINDINGS` (full text shown in the
review conversation, 2026-11-19). Each was checked against the code:
`internal/runtime/containerd/buildkit.go:19` (BuildKit runs as root with
direct containerd access),
`internal/supervisor/lease.go:14` (LeaseGuard), and
`internal/runtime/firecracker/sandbox_snapshot.go:370` (restore of a
stopped sandbox from its memory snapshot) all match.

- **O1** Critical, confidence 8/10 — attestation never checks the image (PCR16): a compromised worker can boot the approved kernel with another image and the victim's sandbox ID. → R10.
- **O2** High, confidence 8/10 — the KMS encryption context names a sandbox but nothing proves the caller is that sandbox; every guest of a team shares the role. → R11.
- **O3** High, confidence 9/10 — verify-then-run of an agent-writable path is a race. → corrected as D4 carried work (root-owned copy).
- **O4** High, confidence 9/10 — BuildKit keeps root-level access to containerd outside the gate. → R13.
- **O5** High, confidence 9/10 — confidential disks use a guest-only key, so M2's "stop keeps the disk" cannot hold for them. → R14.
- **O6** High, confidence 9/10 — overlapping helper generations break per-sandbox order. → corrected as D4 carried work (exclusive handover).
- **O7** High, confidence 6/10, medium confidence — the Firecracker v1.18 bump may strand stopped and paused sandboxes' memory snapshots; whether v1.18 loads v1.15 snapshots is not verified. → R16.
- **O8** High, confidence 8/10 — pod-mode failover has no fence like LeaseGuard; an old sandbox pod can keep running. → R17.

Cross-model agreement: both reviews flagged the helper hot swap (Claude R1;
Codex O3 and O6). Codex found the M3 identity gaps, the BuildKit path, the
confidential Stop contradiction, the snapshot upgrade and the pod-mode fence,
which this review missed. Codex did not comment on the containerd gate.

### R10: Bind secret release to the expected image (outside review O1)
Finding: O1, CRITICAL, confidence 8/10, plans/security-gaps-m1-m4.md §5.2 points 2–5, reviewer Codex (outside voice), checked by /plan-eng-review
Plan baseline: original proposal: the guest measures the image digest into PCR16, but the KMS key policy checks PCR0 and PCR17 only, and the server checker checks PCR0, PCR17, PCR18 and PCR4; D7 (approved) makes the sandbox's OIDC token the only way to call KMS as the team role
Runtime evidence: plan text §5.2 point 4 (key policy conditions) and the server checker list; no PCR16 check anywhere
Comparison grid:
| Choice | Current | A | B | C | D |
|---|---|---|---|---|---|
| R1–R8 | approved (D4–D11) | unchanged | unchanged | unchanged | unchanged |
| R10 what gates the OIDC token and server-held env | PCR0, PCR17, PCR18, PCR4 | the same plus PCR16 equal to the image digest the control plane recorded at create; the token is minted only after this check, so KMS release (D7) inherits it | unchanged (no PCR16 check) | unchanged until a bounded check: write the attack as a test case against the checker design | unchanged; recorded as an open risk |
| R11 sandbox identity in KMS | pending | pending | pending | pending | pending |
Question D12:
D12 — Must a confidential guest prove it runs the right image before it gets secrets?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M3 attestation (outside review O1).
ELI10: The guest writes the image's fingerprint into its attestation, but nobody checks that fingerprint before handing over secrets. A hacked worker machine could start the real AerolVM guest with a different image, claim to be a victim's sandbox, and the checks would pass. That image then receives the victim's secrets.
Stakes if we pick wrong: the confidential tier's main promise breaks: a worker's root could get a customer's secrets.
Recommendation: A because the control plane already records the pinned image digest at create, so one more comparison closes the hole, and D7 makes every KMS call pass through this check.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Apply this change (recommended)
  ✅ A worker cannot swap in its own image: no matching image fingerprint, no token, no secrets
  ✅ One more field compared in a checker that already exists in the plan (human: ~1 day / CC: ~1 hour)
  ❌ Every confidential create must keep its exact image digest in the control plane's record
B) Keep this row's current value
  ✅ No change to the checker or the create record
  ✅ The other checks still stop a guest with the wrong kernel or profile
  ❌ A compromised worker can feed a victim's secrets to an image it chose
C) Investigate before choosing
  ✅ Writes the attack as a checker test case before changing the design
  ✅ Keeps the checker and create record unchanged while the case is written
  ❌ Delays a fix for a hole the evidence already shows
D) Defer this proposed change only
  ✅ M3 starts only after M2 (b), so the gap does not ship soon
  ✅ Leaves the current design and every other choice as they are
  ❌ The plan keeps a known Critical hole on record
Net: one extra comparison versus a confidential tier that leaks to a hacked worker.
Header: Image binding
Options:
A) Apply this change (recommended)
The server mints the sandbox's OIDC token (and releases server-held env for Vault or HSM custody) only after the attestation document shows PCR16 equal to the image digest the control plane recorded at create, plus the existing PCR0, PCR17, PCR18 and PCR4 checks. KMS release inherits this because D7 needs that token. Test: a document with the right PCR0/17/18 and a different PCR16 gets nothing. Effort human ~1 day / CC ~1 hour.
B) Keep this row's current value
Keep the checker as written: PCR0, PCR17, PCR18 and PCR4, no image check.
C) Investigate before choosing
Write the attack as a test case against the checker design first; the checker and create record stay as they are until then.
D) Defer this proposed change only
Leave the design unchanged and record the gap as an open risk for the M3 PRs; every other choice stays as it is.

State: approved
Actual answer: A) Apply this change (recommended), owner answer to D12, 2026-11-19
Accepted scope: the server mints the sandbox's OIDC token and releases server-held env (Vault or HSM custody) only after the attestation document shows PCR16 equal to the image digest the control plane recorded at create, plus PCR0, PCR17, PCR18, PCR4 and a fresh nonce; KMS release inherits the check through D7; test: right PCR0/17/18 with a different PCR16 gets nothing; plan §5.2 point 4 amended
History: none

### R11: Prove the KMS caller is the sandbox the ciphertext belongs to (outside review O2)
Finding: O2, HIGH, confidence 8/10, plans/security-gaps-m1-m4.md §5.2 point 4, reviewer Codex (outside voice), checked by /plan-eng-review
Plan baseline: approved D7: the guest calls KMS as the customer's team role via its own OIDC token; the KMS encryption context carries the sandbox ID; approved D12: the token is minted only after PCR16/17/18/4 checks. Every sandbox of a team assumes the same role, so the role alone does not say which sandbox is calling
Runtime evidence: the OIDC subject is built from an owner ref and a role tag (internal/cloudidentity/doc.go), not a sandbox ID; KMS checks the encryption context only for a match with the one given at encrypt time, and the caller supplies it
Comparison grid:
| Choice | Current | A | B | C | D |
|---|---|---|---|---|---|
| R1–R10 | approved (D4–D12) | unchanged | unchanged | unchanged | unchanged |
| R11 how KMS knows which sandbox is calling | it does not | the OIDC token carries the sandbox ID as an AWS session tag (the `https://aws.amazon.com/tags` claim), and the key policy requires `kms:EncryptionContext:sandbox` to equal `${aws:PrincipalTag/sandbox}`; the token is minted only for the attested PCR18 sandbox (D12) | unchanged | unchanged until a bounded check: one live KMS test that session-tag matching works with web identity | unchanged; recorded as an open risk |
Question D13:
D13 — Must KMS check that the caller is the very sandbox the secret belongs to?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M3 secret release (outside review O2).
ELI10: Every sandbox of one team signs its KMS calls with the same team role. The secret is locked to a sandbox ID, but the caller just says which ID it wants. So any attested sandbox of that team could ask for another sandbox's secret by naming it. The fix stamps the sandbox ID onto the caller's AWS session, so KMS compares the ID the caller asks for with the ID it really is.
Stakes if we pick wrong: one sandbox of a team can read another sandbox's secrets, which a bank would treat as a tenant-isolation failure.
Recommendation: A because AWS session tags from the web-identity token are a standard IAM pattern, and D12 already ensures each token is minted only for the right sandbox.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Apply this change (recommended)
  ✅ KMS itself refuses any sandbox asking for another sandbox's secret, with no AerolVM code in the path
  ✅ Uses AWS session tags from the token AerolVM already mints (human: ~2 days / CC: ~3 hours)
  ❌ Customers' key policies get one more condition, and the token gets a new claim to keep stable
B) Keep this row's current value
  ✅ Simpler key policy and token
  ✅ Isolation between teams still holds, since each team has its own role
  ❌ Sandboxes inside one team can read each other's secrets
C) Investigate before choosing
  ✅ One live KMS test proves session-tag matching works with web identity before the design depends on it
  ✅ Keeps the token and key policy unchanged until that test passes
  ❌ Delays the design for a pattern AWS documents
D) Defer this proposed change only
  ✅ M3 is months away; nothing ships with the gap soon
  ✅ Every other choice stays as it is
  ❌ The plan keeps a known isolation gap on record
Net: one key-policy condition versus sandboxes of a team reading each other's secrets.
Header: Sandbox binding
Options:
A) Apply this change (recommended)
The server's OIDC token for a sandbox carries its sandbox ID as an AWS session tag (the https://aws.amazon.com/tags claim). The customer's key policy requires kms:EncryptionContext:sandbox to equal ${aws:PrincipalTag/sandbox}, so KMS refuses a guest that names another sandbox. D12 already mints the token only for the attested sandbox. The M3 live test checks a cross-sandbox Decrypt is refused. Effort human ~2 days / CC ~3 hours.
B) Keep this row's current value
Keep D7 as approved: the team role plus the encryption context, with no proof of which sandbox is calling.
C) Investigate before choosing
Run one live KMS test that session tags from a web-identity token can be matched against the encryption context; the design stays unchanged until it passes.
D) Defer this proposed change only
Leave the design unchanged and record the gap as an open risk for the M3 PRs.

State: approved
Actual answer: A) Apply this change (recommended), owner answer to D13, 2026-11-19
Accepted scope: the server's OIDC token for a sandbox carries its sandbox ID as an AWS session tag (https://aws.amazon.com/tags claim); the customer's key policy requires kms:EncryptionContext:sandbox to equal ${aws:PrincipalTag/sandbox}; D12 mints the token only for the attested sandbox; the M3 live test checks a cross-sandbox Decrypt is refused; plan §5.2 point 4 amended
History: none

### R13: Where image builds run once the agent has no root (outside review O4)
Finding: O4, HIGH, confidence 9/10, plans/security-gaps-m1-m4.md §3.1 and §3.4 Q3, reviewer Codex (outside voice), checked by /plan-eng-review
Plan baseline: original proposal: Q3 moves build-context tar extraction to a child process with no rights; buildkitd itself is not mentioned
Runtime evidence: the agent drives builds through buildkitd's socket (internal/runtime/containerd/buildkit.go:19, `unix:///run/buildkit/buildkitd.sock`, `SB_CONTAINERD_BUILDKIT_ADDR`, internal/config/config.go:2421); the VM installer runs buildkitd as root with direct containerd access, outside the gate; the Kubernetes chart runs no buildkitd
Comparison grid:
| Choice | Current | A | B | C | D |
|---|---|---|---|---|---|
| R1–R11 | approved (D4–D13) | unchanged | unchanged | unchanged | unchanged |
| R13 who runs Dockerfile steps | root buildkitd with direct containerd access | rootless buildkitd (BuildKit's rootless mode, OCI worker) with its own network that gets the sandboxes' egress rules | unchanged | unchanged until a bounded spike: rootless buildkitd on AL2023, build time against today, the import path | unchanged; builds recorded as outside M1 |
| R13 how a built image reaches containerd | written directly by buildkitd's containerd worker | exported as an OCI archive and imported by the agent through the gate's allowed transfer import | unchanged | unchanged | unchanged |
| R13 does the agent hold a root-equivalent socket | yes (buildkitd) | no | yes | yes | yes |
Question D14:
D14 — Where should image builds run once the agent has no root?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 and image builds (outside review O4).
ELI10: Tenants can build images from a Dockerfile. On VM installs, the agent sends those builds to BuildKit, which runs as root, and writes straight into containerd, outside the gate. If the agent keeps that BuildKit socket after M1, a broken agent still has a root-level back door, and M1's promise fails on every VM with builds.
Stakes if we pick wrong: M1 claims "tenant-facing code has no root" while the build path keeps a root-level socket.
Recommendation: A because rootless BuildKit is BuildKit's own documented mode, so builds keep working while the agent loses its last root-level socket and build steps get the sandboxes' egress rules.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Apply this change (recommended)
  ✅ The agent holds no root-level socket at all, so M1's claim is true on VMs too
  ✅ Build steps get the same egress rules as sandboxes
  ❌ Rootless BuildKit needs user namespaces and adds an export-import step (human: ~1 week / CC: ~1 day)
B) Keep this row's current value
  ✅ No change to the build path or its speed
  ✅ Kubernetes installs are unaffected, since the chart runs no BuildKit
  ❌ A broken agent keeps root through BuildKit on every VM install
C) Investigate before choosing
  ✅ A short spike measures rootless build time and the import path before committing
  ✅ Nothing changes on the build path until the spike reports
  ❌ The M1 stack cannot claim VMs are covered until it finishes
D) Defer this proposed change only
  ✅ M1's Kubernetes work goes ahead untouched
  ✅ Every other choice stays as it is
  ❌ The plan records builds as an open root path on VMs
Net: a rootless build path versus a root-level socket the split leaves behind.
Header: Image builds
Options:
A) Apply this change (recommended)
Run buildkitd rootless (BuildKit's rootless mode, OCI worker) with its own network that gets the sandboxes' egress rules. The build exports an OCI archive; the agent imports it through the gate's allowed transfer import. The agent no longer holds any root-level socket. Effort human ~1 week / CC ~1 day.
B) Keep this row's current value
Keep root buildkitd with direct containerd access; the agent keeps its socket.
C) Investigate before choosing
Spike rootless buildkitd on AL2023: build time against today and the import path; the build path stays as it is until then.
D) Defer this proposed change only
Leave the build path unchanged and record builds as outside M1 on VM installs.

State: approved
Actual answer: A) Apply this change (recommended), owner answer to D14, 2026-11-19
Accepted scope: buildkitd runs rootless (OCI worker) with its own network that gets the sandboxes' egress rules; a build exports an OCI archive the agent imports through the gate's allowed transfer import; the agent holds no root-level socket on VM installs; new M1 PR 10b; plan §3.4 Q3 and §3.5 amended
History: evidence wording trimmed on 2026-11-20 before the plan was published; the decision and its scope are unchanged

### R14: What Stop and Start mean for a confidential sandbox (outside review O5)
Finding: O5, HIGH, confidence 9/10, plans/security-gaps-m1-m4.md §4.3 against §5.2 point 3, reviewer Codex (outside voice), checked by /plan-eng-review
Plan baseline: §4.3 (Nitro backend): Stop keeps the disk and drops memory, Start cold-boots from the kept disk, moves use the disk; §5.2 point 3 (M3 v1): the writable disk is encrypted with a key from the NSM's random source that never leaves the guest
Runtime evidence: plan text only; the two rules contradict for confidential sandboxes, because the key dies with the guest at Stop
Comparison grid:
| Choice | Current | A | B | C | D |
|---|---|---|---|---|---|
| R1–R13 | approved (D4–D14) | unchanged | unchanged | unchanged | unchanged |
| R14 Stop, Start, Pause, move for a confidential sandbox | contradictory (disk kept but unreadable) | refused with `409 confidential_ephemeral` and a reason; decommission recreates; destroy is the only end; docs say so | unchanged (contradiction stays) | unchanged until a bounded design: a disk key wrapped by KMS and released under the D12/D13 checks, so a cold Start can reopen the disk | unchanged; recorded as an open issue |
| R14 confidential disk key | never leaves the guest | never leaves the guest | never leaves the guest | unchanged until the design is done | never leaves the guest |
Question D15:
D15 — What should Stop and Start do for a confidential sandbox?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M3 lifecycle (outside review O5).
ELI10: For Nitro VMs the plan says Stop keeps the disk and Start boots from it again. But a confidential sandbox locks its disk with a key that only lives inside the running guest. Stop kills the guest and the key with it, so the kept disk can never be read again. The plan promises both things.
Stakes if we pick wrong: a customer stops a confidential sandbox and finds its data gone, with no error at Stop time.
Recommendation: A because v1 already gives up snapshots on Nitro, and refusing Stop clearly is safer than a Stop that silently destroys data; a wrapped key can come later.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Apply this change (recommended)
  ✅ No silent data loss: the API refuses up front and says why
  ✅ Keeps the strongest key rule: the disk key never leaves the guest
  ❌ Confidential sandboxes cannot be stopped and resumed in v1 (human: ~1 day / CC: ~1 hour)
B) Keep this row's current value
  ✅ No change to the plan text
  ✅ Non-confidential Nitro sandboxes keep cold Stop and Start either way
  ❌ Stop on a confidential sandbox silently makes its disk unreadable
C) Investigate before choosing
  ✅ Designs a KMS-wrapped disk key released under D12 and D13, so cold Start could work
  ✅ Leaves the current rules in place while the design is written
  ❌ The contradiction stays in the plan until that design lands
D) Defer this proposed change only
  ✅ M3 is months away; nothing ships with the gap soon
  ✅ Every other choice stays as it is
  ❌ The plan keeps a known data-loss path on record
Net: an honest refusal now versus a Stop that loses data.
Header: Confidential stop
Options:
A) Apply this change (recommended)
Confidential sandboxes are ephemeral in v1: their disk key never leaves the guest; Stop, Start, Pause and moves answer 409 confidential_ephemeral with a reason; decommission recreates; destroy is the only end. The docs page and API reference say so. Effort human ~1 day / CC ~1 hour.
B) Keep this row's current value
Keep §4.3 and §5.2 as written, with the contradiction.
C) Investigate before choosing
Design a disk key wrapped by KMS and released only under the D12/D13 checks, so a cold Start can reopen the disk; the current rules stay until the design is done.
D) Defer this proposed change only
Leave the plan unchanged and record the contradiction as an open issue for the M3 PRs.

State: approved
Actual answer: superseded by the owner's answer C to D19 (T2), 2026-11-20
Accepted scope: confidential sandboxes keep their disk across Stop, Start and disk-only moves through a KMS-wrapped disk key released only under the D12/D13 checks; Pause answers 409 with a reason (Nitro cannot snapshot); plan §5.2 point 3 amended
History: D15 answer A) Apply this change (recommended), 2026-11-19, accepted scope: ephemeral confidential sandboxes, Stop/Start/Pause/moves refused with 409 confidential_ephemeral; replaced on 2026-11-20 by the owner's explicit choice C in D19 ("Replace D15's refusal in M3 v1 with the KMS-wrapped disk key")

### R16: Stopped and paused Firecracker sandboxes across the v1.18 bump (outside review O7)
Finding: O7, HIGH, confidence 6/10 (medium confidence, verify), plans/security-gaps-m1-m4.md §4.3 Firecracker pin row, reviewer Codex (outside voice), checked by /plan-eng-review
Plan baseline: §4.3: pin v1.18.x for both backends; template snapshots are rebuilt on first use; a move between two different versions is refused with a reason
Runtime evidence: Stop and Pause always write a memory snapshot and Start always restores it (internal/runtime/firecracker/sandbox_snapshot.go:370 `startFromSandboxSnapshot`); Firecracker v1.16.2 bumped the snapshot format (CHANGELOG: "Snapshots created by this version cannot be loaded by 1.16.0 or 1.16.1"); whether v1.18 loads a v1.15.1 snapshot is not stated in the pages read; moves refused across versions would also block draining old workers during the upgrade
Comparison grid:
| Choice | Current | A | B | C | D |
|---|---|---|---|---|---|
| R1–R14 | approved (D4–D15) | unchanged | unchanged | unchanged | unchanged |
| R16 restoring a sandbox snapshot made by v1.15.1 | unplanned (may fail after the bump) | each sandbox snapshot records the Firecracker version that made it; restore runs that version's binary; nodes ship v1.15.1 next to v1.18.x until a metric shows no v1.15 snapshots remain; SP-A first checks whether v1.18 loads v1.15 snapshots, and if it does the second binary is dropped | unchanged | unchanged until SP-A checks whether v1.18 loads a v1.15.1 snapshot | unchanged; recorded as an open risk |
| R16 moves during the upgrade | refused across versions | a move targets a node that has the snapshot's version | unchanged | unchanged | unchanged |
Question D16:
D16 — How do stopped Firecracker sandboxes survive the Firecracker upgrade?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M2 Firecracker v1.18 bump (outside review O7).
ELI10: Nitro needs Firecracker 1.18; we run 1.15.1. A stopped or paused Firecracker sandbox is saved as a memory snapshot, and newer Firecracker changed the snapshot format. If 1.18 cannot read a 1.15 snapshot, every stopped sandbox loses its memory at the upgrade, and the plan only rebuilds template snapshots. Nobody has checked yet whether 1.18 can read them.
Stakes if we pick wrong: customers' paused sandboxes fail to resume after an upgrade, and old workers cannot be drained.
Recommendation: A because it is safe whichever way the check comes out, and SP-A's check removes the second binary if it turns out not to be needed.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Apply this change (recommended)
  ✅ No stopped sandbox loses its memory, whatever the format check shows
  ✅ Drains keep working: a move picks a node that can read the snapshot
  ❌ Two Firecracker binaries per node for a while, chosen per snapshot (human: ~3 days / CC: ~4 hours)
B) Keep this row's current value
  ✅ One Firecracker binary; simplest upgrade
  ✅ Template snapshots are rebuilt as planned
  ❌ If 1.18 cannot read 1.15 snapshots, every paused sandbox breaks at the upgrade
C) Investigate before choosing
  ✅ SP-A answers the format question in one extra step at no extra cost
  ✅ No second binary is built unless it turns out to be needed
  ❌ Leaves the fix undecided until SP-A runs
D) Defer this proposed change only
  ✅ The KVM bump happens only with M2 (b); nothing ships soon
  ✅ Every other choice stays as it is
  ❌ The plan keeps a possible data-loss path on record
Net: two binaries for a while versus betting paused sandboxes on an unchecked format.
Header: FC snapshots
Options:
A) Apply this change (recommended)
Each sandbox snapshot records the Firecracker version that made it, and restore runs that version's binary. Nodes ship v1.15.1 next to v1.18.x until a metric shows no v1.15 snapshots remain. A move targets a node with the snapshot's version. SP-A first checks whether v1.18 loads a v1.15.1 snapshot; if it does, the second binary is dropped. Effort human ~3 days / CC ~4 hours.
B) Keep this row's current value
Keep §4.3 as written: one v1.18 binary, template snapshots rebuilt, cross-version moves refused.
C) Investigate before choosing
Add one step to SP-A: load a v1.15.1 sandbox snapshot in v1.18. The plan stays as written until the result is in.
D) Defer this proposed change only
Leave §4.3 unchanged and record the risk for the M2 (b) PRs.

State: approved
Actual answer: superseded by owner requirement R18, 2026-11-20 (the KVM backend keeps v1.15.1, so its snapshots never meet v1.18)
Accepted scope: the KVM backend stays on v1.15.1; v1.18.x ships only on Nitro node pools; D16's per-snapshot version rule applies only if the KVM backend is later moved to v1.18; the SP-A step that loads a v1.15.1 snapshot in v1.18 is dropped; plan §4.2 and §4.3 amended
History: D16 answer A) Apply this change (recommended), 2026-11-19, accepted scope: pin v1.18 for both backends, two binaries per node chosen per snapshot until no v1.15 snapshots remain; reopened 2026-11-20 because the owner required that new options never replace the existing fast path

### R17: A fence for pod-mode failover (outside review O8)
Finding: O8, HIGH, confidence 8/10, plans/security-gaps-m1-m4.md §6.2 and §6.4 ("Failover recreates, because a rescheduled pod is a new sandbox"), reviewer Codex (outside voice), checked by /plan-eng-review
Plan baseline: original proposal: a pod-mode worker is a StatefulSet replica; failover recreates; pod name = sandbox ID; approved D8: toolboxd trusts only its named worker over mTLS
Runtime evidence: today `LeaseGuard` (internal/supervisor/lease.go:14) freezes a sandbox once sandboxd's ownership lease runs out, so a sandbox the cluster may recreate elsewhere stops running here even with sandboxd down; pod mode has no such fence, and a pod on an unreachable node can stay running and stuck in Terminating
Comparison grid:
| Choice | Current | A | B | C | D |
|---|---|---|---|---|---|
| R1–R16 | approved (D4–D16) | unchanged | unchanged | unchanged | unchanged |
| R17 what stops the old copy before a recreate | nothing | two fences: toolboxd (PID 1 of the sandbox container, `restartPolicy: Never`) holds a lease its worker renews over the D8 mTLS link and ends the sandbox's processes when it lapses; the new owner recreates only after Kubernetes confirms the old pod is gone, or after the lease has lapsed plus a grace period | nothing | unchanged until a bounded design check against LeaseGuard's rules | unchanged; recorded as an open risk for M4 |
| R17 name clash with a surviving pod | recreate blocked by the same pod name | the old pod is gone or fenced before the new one is created under that name | blocked | unchanged | unchanged |
Question D17:
D17 — What makes sure a pod-mode sandbox's old copy has stopped before it is recreated?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M4 failover (outside review O8).
ELI10: In the default install, if a worker's agent dies, a guard on the machine freezes its sandboxes once the agent's lease runs out, so no sandbox runs in two places. In pod mode each sandbox is a pod, and a dead worker does not stop its pods. If the cluster recreates the sandbox elsewhere, two copies can run at once, and a stuck old pod can block the new one, which has the same name.
Stakes if we pick wrong: two copies of one sandbox run at once, writing to the same storage or racing on external effects.
Recommendation: A because it copies the lease rule the default install already trusts, and the second fence (confirmed delete) covers a node that cannot be reached.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Apply this change (recommended)
  ✅ Never two copies: the old one stops by lease even on a node Kubernetes cannot reach
  ✅ Same rule as LeaseGuard, so both installs behave alike for operators
  ❌ toolboxd gains a lease loop, and recreate waits up to the lease time plus grace (human: ~4 days / CC: ~6 hours)
B) Keep this row's current value
  ✅ No lease code in toolboxd
  ✅ Recreate is as fast as Kubernetes can schedule a pod
  ❌ Two copies of a sandbox can run at once after a worker failure
C) Investigate before choosing
  ✅ Checks the design against LeaseGuard's rules before writing toolboxd code
  ✅ Leaves pod mode's design as it is while the check runs
  ❌ M4's failover stays unsafe on paper until the check ends
D) Defer this proposed change only
  ✅ M4 is built only on a buyer trigger, so nothing ships with the gap soon
  ✅ Every other choice stays as it is
  ❌ The plan keeps a known split-brain path on record
Net: a lease fence like the default install's versus two copies after a failure.
Header: Pod-mode fence
Options:
A) Apply this change (recommended)
toolboxd, PID 1 of the sandbox container with restartPolicy Never, holds a lease its worker renews over the D8 mTLS link and ends the sandbox's processes when it lapses. The new owner recreates only after Kubernetes confirms the old pod is gone, or after the lease has lapsed plus a grace period. Tests: a partitioned worker's sandbox stops by itself; a recreate waits for the fence. Effort human ~4 days / CC ~6 hours.
B) Keep this row's current value
Keep §6 as written: failover recreates with no fence.
C) Investigate before choosing
Check a fence design against LeaseGuard's rules (internal/supervisor/lease.go) first; pod mode's design stays as it is until then.
D) Defer this proposed change only
Leave §6 unchanged and record the split-brain risk for the M4 build.

State: approved
Actual answer: A) Apply this change (recommended), owner answer to D17, 2026-11-19
Accepted scope: toolboxd, PID 1 of the sandbox container with restartPolicy Never, holds a lease its worker renews over the D8 mTLS link and ends the sandbox's processes when it lapses; the new owner recreates only after Kubernetes confirms the old pod is gone, or after the lease has lapsed plus a grace period; tests: a partitioned worker's sandbox stops by itself, a recreate waits for the fence; plan §6.4 amended
History: none

### Outside voice dispositions
O1 → R10 accepted (D12, A); O2 → R11 accepted (D13, A); O3 corrected (D4 carried work); O4 → R13 accepted (D14, A); O5 → R14 accepted (D15, A); O6 corrected (D4 carried work); O7 → R16 accepted (D16, A); O8 → R17 accepted (D17, A). Review log: codex-plan-review, issues_found, outside_status completed.

### T1: TODO — worker machines prove what they booted (M3c)
Finding: plan §5.2 point 8 (M3c, "build it only when a buyer asks"), reviewer /plan-eng-review (Claude)
Plan baseline: M3c is described in the plan but has no TODO entry, so the "on request" trigger is not tracked
Runtime evidence: EC2 instance attestation needs an attestable AMI (Amazon Linux 2023 or NixOS built with KIWI NG, UEFI, NitroTPM); the EC2 pages do not mention the EKS-optimized AMI or Bottlerocket; today nodes join with TokenReview plus mTLS (plans/kubernetes-v2-architecture.md §15.2)
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R17 | approved (D4–D17) | unchanged | unchanged | unchanged |
| T1 tracking of NitroTPM node attestation | plan text only | a P3 entry in TODOS.md (Kubernetes section) with What/Why/Pros/Cons/Effort/Priority/Depends on, trigger: a buyer asks | no TODO | built inside this plan's M3 v1 |
Question D18:
D18 — Track "worker machines prove what they booted" (M3c) as a TODO?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, TODO for M3c.
ELI10: AWS can sign a statement that a machine booted an exact, approved disk image. AerolVM could ask for that before letting a worker join the cluster. It means building and shipping our own special worker image for EKS, which is a lot of ops work. The plan says to do it only when a buyer asks, but nothing tracks that.
Stakes if we pick wrong: the idea is lost, or ops work starts before any buyer needs it.
Recommendation: A because a TODO keeps the trigger visible at no cost, while the AMI work waits for a buyer.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ The "buyer asks" trigger is tracked where the team looks for deferred work
  ✅ Costs nothing now; the AMI work waits for real demand
  ❌ One more P3 entry in a long TODO file
B) Skip
  ✅ TODOS.md stays shorter
  ✅ The plan text still describes M3c
  ❌ Nobody is reminded when a buyer asks for node attestation
C) Build it now in this plan
  ✅ Closes the node half of the attestation row at once
  ✅ Pairs with M3 v1's guest attestation for a complete story
  ❌ Building and shipping an attestable EKS worker AMI is large ops work with no buyer yet (human: ~3 weeks / CC: ~3 days)
Net: a tracked trigger versus building an AMI pipeline before anyone asks.
Header: TODO M3c
Options:
A) Add to TODOS.md (recommended)
Add a P3 entry in the Kubernetes section: NitroTPM node attestation with an attestable EKS worker AMI (KIWI NG, AL2023), checked in the join flow before a node certificate; trigger: a buyer asks. Effort L.
B) Skip
No TODO; M3c stays as plan text only.
C) Build it now in this plan
Move M3c into M3 v1's scope: build the attestable worker AMI and add the NitroTPM check to the join flow.

State: approved
Actual answer: A) Add to TODOS.md (recommended), owner answer to D18, 2026-11-19
Accepted scope: a P3 entry "Worker machines prove what they booted: NitroTPM node attestation (Kubernetes, P3)" added to TODOS.md after the pod mode entry; trigger: a buyer asks
History: none

### T2: TODO — let confidential sandboxes stop and start (wrapped disk key)
Finding: follow-up of R14 (D15): confidential sandboxes are ephemeral in v1, reviewer /plan-eng-review (Claude)
Plan baseline: approved D15: Stop, Start, Pause and moves answer 409 confidential_ephemeral; the disk key never leaves the guest
Runtime evidence: Nitro confidential VMs cannot snapshot (EC2 guide, Lifecycle); a cold Start could reopen a kept disk only if its key survives the guest, for example wrapped by KMS and released under the D12/D13 checks
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R17, T1 | approved (D4–D18) | unchanged | unchanged | unchanged |
| T2 tracking of cold Stop/Start for confidential sandboxes | none | a P3 entry in TODOS.md: a disk key wrapped by KMS, released only under the D12/D13 checks, so a cold Start can reopen the disk; trigger: a buyer needs to stop and resume confidential sandboxes | no TODO | built in M3 v1, replacing D15's refusal |
Question D19:
D19 — Track "let confidential sandboxes stop and start" as a TODO?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, TODO after D15.
ELI10: You chose to make confidential sandboxes refuse Stop and Start in v1, because their disk key dies with the guest. A later version could lock that key with KMS so only the same, re-attested sandbox can unlock it after a restart. That is real work, and today no buyer has asked for it.
Stakes if we pick wrong: the follow-up is forgotten, or M3 v1 grows before anyone needs stop and resume.
Recommendation: A because it records the path from "refused" to "works" without growing M3 v1.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ The way to lift D15's refusal is written down for when a buyer asks
  ✅ M3 v1 stays the size you approved
  ❌ One more P3 entry in a long TODO file
B) Skip
  ✅ TODOS.md stays shorter
  ✅ D15's ledger entry already explains the limit
  ❌ The follow-up design lives only in a review ledger nobody reads later
C) Build it now in this plan
  ✅ Confidential sandboxes could stop and resume from M3 v1 on
  ✅ Reuses the D12/D13 release path that M3 v1 builds anyway
  ❌ Reverses D15 and grows M3 v1 by a key-wrapping flow and its tests (human: ~1 week / CC: ~1 day)
Net: a tracked follow-up versus growing M3 v1 now.
Header: TODO disk key
Options:
A) Add to TODOS.md (recommended)
Add a P3 entry: confidential sandboxes stop and start with a disk key wrapped by KMS and released only under the D12/D13 checks, so a cold Start reopens the disk; trigger: a buyer needs stop and resume for confidential sandboxes. Effort M.
B) Skip
No TODO; D15's refusal stays, explained only in this ledger.
C) Build it now in this plan
Replace D15's refusal in M3 v1 with the KMS-wrapped disk key.

State: approved
Actual answer: C) Build it now in this plan, owner answer to D19, 2026-11-20 (against the recommendation of A)
Accepted scope: M3 v1 wraps each confidential sandbox's disk key with the customer's KMS key (team role, encryption context sandbox=<id>, purpose=disk); the host keeps only the ciphertext; a cold Start or disk-only move gets the key back only through the D12 and D13 checks; Stop, Start and disk-only moves work for confidential sandboxes; Pause still answers 409; replaces D15's refusal; tests: a cold Start reopens the disk, another sandbox and a guest with the wrong PCR16 cannot unwrap the key; plan §5.2 point 3 and R14 updated; no TODO added
History: none

### C3: pod mode TODO refreshed (correction)
TODOS.md's pod mode entry said "design first"; the design is now §6 of this plan with D8 and D17, and spike S9 failed on EKS 1.36. The entry now says so. No behavior change, no question.



### R18: Every new option is an add-on (owner requirement)
Finding: owner statement in the review conversation, 2026-11-20: "I am hoping it doesn't replace my existing approach. It will be an add-on ... There should be a config present which should help me to select different strategies."
Plan baseline: KVM stayed the default backend, but §4.3 moved both backends to Firecracker v1.18 (with D16's two-binary rule), no runtime name selected Nitro, and §4.1 said Nitro has no warm pool
Runtime evidence: today's Firecracker warm pool loads template snapshots into paused VMMs (internal/runtime/firecracker/warmspawn.go header), which Nitro cannot do; Nitro and nested virtualization cannot share an instance, so pools are separate anyway
Accepted scope (owner requirement, no option menu): every new strategy is opt-in behind a setting; the KVM backend keeps v1.15.1 and its whole fast path; v1.18 only on Nitro node pools; Nitro gets its own runtime name (`firecracker-nitro`, final name in the PR) and `firecracker` keeps today's meaning; no silent fallback between backends; a selection table added to §1; D16 superseded (see R16). Open follow-ups: D21 (a parked warm pool for Nitro), D22 (whether M1 is a setting too)
State: approved
Actual answer: owner requirement, 2026-11-20
History: none

### R19: A warm pool for Nitro Firecracker
Finding: owner concern 2026-11-20 ("warm boot will not happen"); reviewer /plan-eng-review (Claude)
Plan baseline: §4.1 said Nitro has no warm pool; Nitro creates always cold-boot (SP-B go bar: under 2 s)
Runtime evidence: today's warm pool needs snapshots (internal/runtime/firecracker/warmspawn.go: LoadSnapshot into a paused VMM), which Nitro rejects; a pool of booted, idle VMs needs no snapshot: the containerd warm pool already parks running sandboxes and hands env over on claim (internal/runtime/containerd/warm_adopt.go), and Firecracker creates already finish with a vsock handshake, env and adoptGuest (driver.go); Nitro limits: at least 256 MiB per VM, 5 VMs per vCPU, memory from the boot-time pool
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R18 | approved (D4–D19, R18) | unchanged | unchanged | unchanged |
| R19 warm creates on Nitro | none; every create cold-boots | a parked pool: N VMs per image booted ahead of time with toolboxd waiting; a claim does the vsock handshake, pushes env and adopts the guest; off by default, set per Nitro node pool (pool size per image); parked VMs count toward the 5-per-vCPU and memory-pool limits | none (cold boot only) | none until SP-B measures a parked claim on Nitro |
| R19 effect on KVM Firecracker | none | none (separate pool type, Nitro nodes only) | none | none |
Question D21:
D21 — Should Nitro Firecracker get its own warm pool of pre-booted VMs?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M2 (b) warm creates.
ELI10: Your current Firecracker warm pool works by loading saved snapshots, and Nitro can't load snapshots, so that pool can't work there. But we can still keep a few Nitro VMs already booted and idle, with the toolbox waiting inside. A create then just hands one over: connect, send the env, done. Your KVM pool is not touched. The cost is that idle VMs use memory and count toward Nitro's limit of 5 VMs per vCPU.
Stakes if we pick wrong: Nitro creates always pay a full boot (about a second or more), or idle VMs waste a pool's memory when nobody uses Nitro.
Recommendation: A because it brings Nitro creates close to warm speed, stays off by default, and never touches your KVM fast path.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Parked pool, off by default (recommended)
  ✅ Nitro creates skip the boot when a parked VM for that image is ready
  ✅ Off by default and set per Nitro node pool, so nothing changes unless you turn it on
  ❌ Parked VMs hold memory and use up part of the 5-per-vCPU limit (human: ~1 week / CC: ~1 day)
B) Cold boot only
  ✅ Simplest Nitro backend; no idle VMs to manage
  ✅ All of a Nitro node's capacity goes to real sandboxes
  ❌ Every Nitro create pays a full boot, unmeasured but about a second or more
C) Measure first in SP-B
  ✅ SP-B times a parked claim on a real Nitro node before any code is written
  ✅ Nothing is built until the number is known
  ❌ The Nitro backend's warm design stays open until the spike runs
Net: a parked pool you turn on when you need it versus a boot on every Nitro create.
Header: Nitro warm pool
Options:
A) Parked pool, off by default (recommended)
Each Nitro node pool can keep N VMs per image booted ahead of time, with toolboxd waiting inside. A claim does the vsock handshake, pushes env and adopts the guest. Off by default; pool size set per Nitro node pool and image. Parked VMs count toward the 5-per-vCPU and memory-pool limits. Your KVM snapshot pool is untouched. Effort human ~1 week / CC ~1 day.
B) Cold boot only
Keep the plan as written: every Nitro create boots a fresh VM; no Nitro warm pool.
C) Measure first in SP-B
Add a step to SP-B that times a parked claim on a Nitro node; decide after the number is known.

State: approved
Actual answer: A) Parked pool, off by default (recommended), owner answer to D21, 2026-11-20
Accepted scope: each Nitro node pool can keep N VMs per image booted ahead of time with toolboxd waiting; a claim does the vsock handshake, pushes env and adopts the guest; off by default, pool size per Nitro node pool and image; parked VMs count toward the 5-per-vCPU and memory-pool limits; the KVM snapshot warm pool is untouched; SP-B times a parked claim; plan §4.1, §4.3 and the §1 selection table amended
History: none

### R20: Is the root split (M1) a setting too?
Finding: owner requirement R18 (every new option is an add-on) against approved D5 (dual mode for at least one release, then split only); reviewer /plan-eng-review (Claude)
Plan baseline: approved D5: the agent runs split mode when the helper socket exists and today's single root process otherwise, for at least one release after the chart flips; after that, split only
Runtime evidence: M1's cost on the create path is budgeted at ≤1 ms warm / ≤3 ms cold p50 (§3.7, not yet measured); keeping the single-process mode means keeping the code that parses tenant input as root, and testing every root path in both modes
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R19 | approved (D4–D21, R18) | unchanged | unchanged | unchanged |
| R20 a lasting setting for M1 | none (dual mode only during the switch, D5) | `privilegeMode: split \| single`, kept for good | `privilegeMode: split \| single`, kept for good | none: split only after the D5 release |
| R20 default for new installs | split (after D5) | split | single (today's mode) | split |
| R20 existing installs on upgrade | moved to split node by node (D5) | keep their current mode until the operator switches | keep single | moved to split node by node (D5) |
| R20 test matrix | both modes for one release | both modes for good | both modes for good | one mode after one release |
Question D22:
D22 — Should the root split (M1) be a setting you can turn off?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, M1 and the add-on rule.
ELI10: M1 changes how the worker runs: the part that reads customer requests stops running as root, and a small root helper does the root work. Unlike Nitro, confidential mode and pod mode, it is not a new option next to the old one; it changes the default. You asked for new things to be add-ons. We can keep a setting that picks the old single-process mode or the new split, but then both modes must be tested and kept working for good.
Stakes if we pick wrong: either banks still see "tenant input parsed as root" by default, or the team carries two modes of every root path forever.
Recommendation: A because new installs get the safer default banks look for, while existing installs keep running exactly as today until you choose to switch.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Setting, split for new installs (recommended)
  ✅ Existing installs keep today's mode on upgrade; nothing changes until you switch
  ✅ New installs and bank evaluations get the split by default, which closes the matrix row
  ❌ Both modes are tested and kept working for good (human: ~1 week extra over time / CC: ~1 day)
B) Setting, today's mode by default
  ✅ Nothing changes for anyone unless they turn the split on
  ✅ No surprise for any existing operator or script
  ❌ The default install still parses tenant input as root, so the security row stays red
C) No setting (as approved in D5)
  ✅ One mode to test and maintain after the switch release
  ✅ The root-parsing path is removed entirely, which is the strongest security claim
  ❌ Every install moves to the split; there is no way back to today's mode
Net: a safe default with a way to keep today's mode versus one simpler code path.
Header: M1 setting
Options:
A) Setting, split for new installs (recommended)
Keep a lasting setting privilegeMode: split | single (chart value and SB_ setting). New installs default to split. Existing installs keep their current mode on upgrade until the operator switches; the switch rolls workers node by node as in D5. Both modes stay tested. Effort human ~1 week over time / CC ~1 day.
B) Setting, today's mode by default
Keep the same setting, but every install defaults to single (today's mode); split is opt-in.
C) No setting (as approved in D5)
Keep D5: dual mode only for the switch release, then split only. No lasting setting.

State: approved
Actual answer: A) Setting, split for new installs (recommended), owner answer to D22, 2026-11-20
Accepted scope: a lasting setting privilegeMode: split | single (chart value and SB_ setting); new installs default to split; existing installs keep their current mode on upgrade until the operator switches; switching rolls workers node by node as in D5; both modes stay tested, including a mixed fleet; plan §1 selection table and §3.3 "Upgrades" amended; R2 history updated
History: none

### R21: How people discover and pick each option (owner request)
Finding: owner request 2026-11-20 ("You also need to design a plan for the discoverability of these two features ... have we worked on that"); reviewer /plan-eng-review (Claude)
Plan baseline: no discoverability design; §1 has a selection table for the plan's readers only
Runtime evidence: nodes advertise supported_runtimes (pkg/capacity/capacity.go:206), used by placement (internal/cluster/placement.go:558); GET /v1/capacity shows one node's list (pkg/api/v1/handlers.go:40); runtime names at pkg/models/types.go:161 and :304; Kubernetes view maps runtime to runtimeClassName 1:1 (internal/kubeapi/render.go:62); no cluster-wide list, no SDK method, no comparison docs page
Comparison grid:
| Choice | Current | A | B | C |
|---|---|---|---|---|
| R1–R20 | approved (D4–D22, R18) | unchanged | unchanged | unchanged |
| R21 API | none | GET /v1/runtimes from one feature table in pkg/models; tenants see names, features, availability; fleet admins see pool capacity | none | GET /v1/runtimes, same rules |
| R21 SDKs, CLI, MCP | none | runtimes.list() in five SDKs, aerolvm get runtimes, MCP list_runtimes | none | none |
| R21 create feedback | runtime only, plus Server-Timing | sandbox fields backend and warm; a refusal names the offered runtimes | none | refusal names the offered runtimes |
| R21 operator report | none | preflight and aerolvm k8s verify per pool; chart install notes; aerolvm get nodes shows runtimes, backend, privilegeMode | same operator report | none |
| R21 docs | one page per runtime | choose-isolation.mdx comparison page with five SDK tabs; Kubernetes child page "Node pools for each option"; EVIDENCE.md table; a test keeps the docs table equal to the code table | the same docs pages, written by hand | the same docs pages |
Question D23:
D23 — How far should discoverability go?
Project/branch/task: plans/security-gaps-m1-m4, eng review of plans/security-gaps-m1-m4.md, new §11 discoverability.
ELI10: Once Nitro lands, a cluster can offer two kinds of Firecracker plus gVisor, WASM and V8, and maybe confidential and pod mode. Today nothing tells a developer which of these this cluster has or what each can do, and nothing tells an operator why a node pool offers one and not another. The new §11 adds a list API with SDK, CLI and agent support, clearer create results and errors, an operator report per node pool, and one docs page that compares every option.
Stakes if we pick wrong: people keep asking for the default and never find the new options, or pick one that cannot do what they need (pause, warm start).
Recommendation: A because the data already exists in each node's capacity report, so the API is a small read-only addition, and one feature table in code keeps the API, errors and docs from drifting.
Completeness: A=10/10, B=5/10, C=7/10
Pros / cons:
A) Full set (recommended)
  ✅ Developers, agents, operators and evaluators each get the answer where they already look
  ✅ One feature table in code feeds the API, errors and docs, so they never disagree
  ❌ Five PRs, including an SDK method in five languages (human: ~2 weeks / CC: ~2 days)
B) Docs and operator report only
  ✅ No API or SDK change; v1 stays untouched
  ✅ Operators still see why each node pool offers what it does
  ❌ Developers and agents cannot ask the cluster what it offers; the docs table can drift from the code
C) API and docs, no SDK, CLI or MCP
  ✅ The cluster can answer "what do you offer" over plain API calls
  ✅ Smaller than the full set: no five-language SDK change
  ❌ SDK users and agents must call a raw route, which the docs rules discourage
Net: one small read-only API that feeds everything versus docs written by hand.
Header: Discoverability
Options:
A) Full set (recommended)
GET /v1/runtimes from one feature table in pkg/models (tenants see names, features, availability; fleet admins also see pool capacity); runtimes.list() in all five SDKs, aerolvm get runtimes and an MCP list_runtimes tool; sandbox fields backend and warm; refusals that name the offered runtimes; a per-pool operator report in preflight, aerolvm k8s verify, chart notes and aerolvm get nodes; the choose-isolation.mdx page, a Kubernetes child page and an EVIDENCE.md table, with a test that keeps the docs table equal to the code table. Five PRs. Effort human ~2 weeks / CC ~2 days.
B) Docs and operator report only
The comparison docs page, the Kubernetes child page, EVIDENCE.md and the per-pool operator report. No API, SDK, CLI or MCP change.
C) API and docs, no SDK, CLI or MCP
GET /v1/runtimes from the same feature table, refusals that name the offered runtimes, and the docs pages. No SDK method, CLI command or MCP tool.

State: approved
Actual answer: A) Full set (recommended), owner answer to D23, 2026-11-20
Accepted scope: plan §11 as written: GET /v1/runtimes from one feature table in pkg/models (tenants see names, features, availability; fleet admins also see pool capacity); runtimes.list() in all five SDKs, aerolvm get runtimes, MCP list_runtimes; sandbox fields backend and warm; refusals naming the offered runtimes; per-pool operator report (preflight, aerolvm k8s verify, chart notes, aerolvm get nodes); choose-isolation.mdx, a Kubernetes child page, an EVIDENCE.md table; a test keeps the docs table equal to the code table; five PRs (1 and 5 before M2, 2–4 with M2 (b))
History: none


Approval readiness: PASS (rechecked 2026-11-20) — R1 (D4), R2 (D5, extended by D22), R3 (D6), R4 (D7), R5 (D8), R6 (D9), R8 (D10), R7 (D11), R10 (D12), R11 (D13), R13 (D14), R14 (D15, superseded by D19), R16 (D16, superseded by R18), R17 (D17), T1 (D18), T2 (D19), R18 (owner requirement), R19 (D21), R20 (D22), R21 (D23), structure (D3); corrections C1, C2, C3, R9 and the D4 carried work (O3, O6) need no answer.

## Review outputs (eng review 2026-11-19)

### NOT in scope

- **AKS confidential tier.** M3 rests on Nitro; AKS would need AMD SEV-SNP confidential VMs. No buyer has asked.
- **M3 v2's SDK channel to the guest.** Stays a later step (§5.2 point 5, §7 step 6); v1 refuses host exec and files.
- **M3c NitroTPM node attestation.** Tracked in TODOS.md (D18); built when a buyer asks.
- **The Docker engine (local mode) in M1.** `docker.sock` is root and Docker has no gate; local mode keeps today's model and the docs say so.
- **Per-team worker pools (N6, matrix item S2).** The real limit on what a broken agent reaches (R9), but its own plan item.

### What already exists

- `HostManager` (`internal/network/netns/host.go:20`) is reused as the helper's network API (C2).
- `egress.UnixPeerCheck` (`internal/egress/peercred_linux.go:19`) is reused for the helper's socket.
- `aerolvm-supervisor` (`internal/supervisor`) is already root PID 1 of the `runtime` container; it gains the signed hot-swap (D4).
- `LeaseGuard` (`internal/supervisor/lease.go:14`) is the model for pod mode's fence (D17).
- `pkg/isolate/shim_linux.go` already drops uid, sets no-new-privs and seccomp; Q1 copies it for WASM.
- `internal/cloudidentity` already mints per-sandbox OIDC tokens; M3 uses it for KMS (D7) with a new session-tag claim (D13).
- The Prometheus rules and their test (`setup/prometheus/sandboxd-alerts.yml`, `alerts_test.go`) take the refusal alert (D9).
- BuildKit's rootless mode replaces root buildkitd (D14).
- Rebuilt, not reused: a guest kernel build (none exists today, C1).

### Diagrams

```
M1 after the review (D3, D4, D5, D6, D9, D11)

 tenant input ──► agent (uid 65532, no rights) ──► /run/aerolvm/root.sock ──► root helper ──► containerd ──► shims ──► sandboxes
                  │  dual mode: no socket on an       one gRPC server,          │ typed calls, parallel,
                  │  old pod → in-process root (D5)    one SO_PEERCRED check     │ per-sandbox order (D11)
                  │                                    (D3)                      │ containerd allowlist +
                  │                                                              │ field checks (D6)
                  │                                                              ▼
                  │                                     refusal ──► audit event + metric + alert (D9)
                  │
                  └─ stages signed helper ──► supervisor (PID 1) copies to root-only dir ──► verifies ──► exclusive
                     each release (D4)       (O3)                                                    handover (O6)

M3 secret release after the review (D7, D12, D13, D19)

 guest boots ──► extends PCR16 image, PCR17 profile, PCR18 sandbox ──► attestation doc ──► server checks PCR0/16/17/18/4 + nonce (D12)
     ──► OIDC token (sandbox ID as session tag, D13) sealed to the guest key ──► AssumeRoleWithWebIdentity (team role, D7)
     ──► KMS Decrypt with doc; key policy: role + attestation + EncryptionContext:sandbox = PrincipalTag/sandbox
     ──► env and the wrapped disk key (D19) open only inside the guest
```

Inline diagrams needed when built: the hot-swap handover state machine in `internal/supervisor` (staged → copied → verified → draining old → serving new); the attestation checker's order of checks in the server.

### Failure modes

| New path | Realistic failure | Handling and test | User sees |
|---|---|---|---|
| Agent → helper socket | helper down or restarting | latch + `503`; agent retries idempotent calls (§3.3, D4 tests) | clear `503` |
| Gate refuses a call | drift or compromised agent | audit event, metric, alert (D9); create fails `500` | clear error; operator paged |
| Helper hot swap | bad or unsigned staged binary | supervisor keeps the running helper; refusal tested (D4) | nothing |
| Hot swap mid-burst | old and new helper overlap | exclusive handover; Remove/Realize straddle test (O6) | nothing |
| Old pod, new agent | no helper socket | dual mode, in-process root (D5); tested both modes | nothing |
| Nitro VM limits | 6th VM per vCPU, pool full | admission `429`; pause `409` (§4.3) | clear error |
| Firecracker versions | a KVM snapshot meets v1.18 | cannot happen: the KVM backend stays on v1.15.1 and v1.18 runs only on Nitro pools (R18) | nothing |
| Nitro parked pool | no parked VM for the image, or the pool is empty | the create cold-boots, as without a pool (D21); SP-B times both | slower create, no error |
| `privilegeMode` switch | an operator flips an existing install to `split` | workers move node by node through decommission (D5, D22); both modes tested | nothing |
| Confidential release | wrong image, sandbox or host | no token, no key (D12, D13); checker tests | create fails with a reason |
| Confidential cold Start | KMS unreachable from the guest | start fails; disk stays wrapped (D19) | clear start error |
| Pod-mode worker dies | sandbox pod keeps running | lease fence + confirmed delete (D17) | sandbox recreated once |

Critical gaps (no test, no handling, silent): **0**.

### Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| M1 core (rules, gate, helper, hot swap, dual mode, alerts) | `internal/rootpolicy`, `internal/supervisor`, `internal/runtime/containerd`, `internal/network`, `pkg/docker/netrules`, `pkg/mounts`, `pkg/wasm/worker`, `setup/prometheus` | — |
| M1 rollout (chart, VM units, BuildKit) | `charts/aerolvm`, `scripts`, `Ansible`, `Terraform`, `packaging` | M1 core |
| M2 spikes SP-A, SP-B | `integration-tests/k8s` | — |
| M2 (b) Nitro backend (add-on runtime, parked pool) + kernel CI | `internal/runtime/firecracker`, `pkg/firecracker`, `pkg/capacity`, `internal/nodejoin`, CI | M2 spikes |
| M3 v1 | `cmd/toolboxd`, `internal/cloudidentity`, `internal/service`, `sdk/*`, `docs` | M2 (b) |
| M4 pod mode | `internal/runtime/kubepod`, `cmd/toolboxd`, `charts/aerolvm` | trigger (TODOS.md) |

Lane A: M1 core → M1 rollout. Lane B: M2 spikes → M2 (b) → M3 v1. Lane C: M4 (on trigger).
Execution order: launch A and B together. Merge M1 core before M2 (b)'s jailer work lands (both touch `internal/runtime/firecracker`, M1 PR 9). M3 waits for M2 (b).
Conflict flags: `internal/runtime/firecracker` (A PR 9 and B); `cmd/toolboxd` (M3 and M4); `charts/aerolvm` (A, B, C).

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship.

- [ ] **T1 (P1, human: ~1 week / CC: ~1 day)** — M1 gate — write `internal/rootpolicy` and the containerd allowlist with field checks and the field-pin test
  - Surfaced by: Architecture — R3 (D6), outside review prior art (Kata CVE-2026-77176)
  - Files: `internal/rootpolicy/`, `internal/supervisor/`, `internal/runtime/containerd/security.go`
  - Verify: `go test ./internal/rootpolicy/... ./internal/supervisor/...` incl. the broken-agent suite
- [ ] **T2 (P1, human: ~1 week / CC: ~1 day)** — M1 helper — one gRPC server on `root.sock` with `egress.UnixPeerCheck`, parallel calls with per-sandbox order, 100-create benchmark
  - Surfaced by: Scope D3; Performance — R7 (D11)
  - Files: `internal/supervisor/`, `internal/network/netns/`, `pkg/docker/netrules/`, `pkg/mounts/`
  - Verify: `go test ./internal/supervisor/... -bench Create100`
- [ ] **T3 (P1, human: ~1 week / CC: ~1 day)** — M1 hot swap — signed helper, root-owned copy, exclusive handover
  - Surfaced by: Architecture — R1 (D4); outside review O3, O6
  - Files: `internal/supervisor/`, `cmd/aerolvm-supervisor/`, release workflow signing step
  - Verify: tests for unsigned, older, swapped-after-check binaries and a Remove/Realize straddling a swap
- [ ] **T4 (P1, human: ~1 week / CC: ~1 day)** — M1 setting — lasting `privilegeMode: split | single`; split for new installs, existing installs keep their mode; node-by-node switch
  - Surfaced by: Architecture — R2 (D5); owner requirement R18 → R20 (D22)
  - Files: `pkg/daemon/`, `charts/aerolvm/templates/_workerpod.tpl`, operator rollout
  - Verify: kind proof with a mixed fleet; in-place agent swap onto an old pod
- [ ] **T5 (P1, human: ~1 day / CC: ~1 hour)** — M1 refusals — audit event, `aerolvm_rootd_refusals_total`, alert rule and its test
  - Surfaced by: Code quality — R6 (D9)
  - Files: `internal/supervisor/`, `internal/service/` audit, `setup/prometheus/sandboxd-alerts.yml`, `setup/prometheus/alerts_test.go`
  - Verify: `go test ./setup/prometheus/...`
- [ ] **T6 (P1, human: ~1 week / CC: ~1 day)** — M1 builds — rootless BuildKit with its own network and import through the gate
  - Surfaced by: Outside review O4 → R13 (D14)
  - Files: `internal/runtime/containerd/buildkit.go`, `scripts/install.sh`, `Terraform/`, `Ansible/`
  - Verify: build API test on a VM install; build steps get the sandboxes' egress rules
- [ ] **T7 (P1, human: ~1 day / CC: ~2 hours plus run time)** — M1 proof — regression contract: fake-helper tests, kind proofs, TCP pool regression test, one EKS drill
  - Surfaced by: Tests — R8 (D10)
  - Files: `internal/store/store_test.go`, `internal/service/layer4_bootstrap_test.go`, `integration-tests/k8s/`
  - Verify: `make test`; kind proofs; EKS drill S2, OV-E2, F8, F10, N1 (about $10)
- [ ] **T8 (P2, human: ~2 days / CC: ~3 hours)** — M1 quick wins — Q1 WASM uid/seccomp drop, Q2 mount option allowlists, Q3, Q4
  - Surfaced by: §3.4, inventory (WASM workers run as root)
  - Files: `pkg/wasm/worker/supervisor.go`, `pkg/models/mounts.go`, `internal/runtime/containerd/buildkit.go`, `pkg/api/daytona/toolbox.go`, `pkg/api/runloop/files.go`
  - Verify: `go test ./pkg/wasm/... ./pkg/models/...`
- [ ] **T9 (P2, human: ~2 days / CC: ~4 hours plus run time)** — M2 spikes — SP-A and SP-B (incl. timing a Nitro parked claim, D21)
  - Surfaced by: §4.2; R19 (D21)
  - Files: `integration-tests/k8s/`
  - Verify: numbers written into §4.2 (about $10)
- [ ] **T10 (P2, human: ~3 weeks / CC: ~4 days)** — M2 (b) — Nitro backend as an add-on: `firecracker-nitro` runtime, v1.18 only on Nitro pools (KVM stays v1.15.1), guest kernel CI build, parked warm pool off by default
  - Surfaced by: Scope C1; outside review O7 → R16; owner requirement R18; R19 (D21)
  - Files: `internal/runtime/firecracker/`, `pkg/firecracker/client.go`, `pkg/capacity/`, `internal/nodejoin/`, CI, `packaging/images/versions.env`
  - Verify: `go test ./internal/runtime/firecracker/... ./pkg/capacity/...`; SP-B on a live node
- [ ] **T11 (P2, human: ~3 weeks / CC: ~4 days)** — M3 v1 — attestation checker with PCR16, OIDC role with sandbox session tag, wrapped disk key
  - Surfaced by: Architecture — R4 (D7); outside review O1, O2, O5 → R10 (D12), R11 (D13), R14/T2 (D19)
  - Files: `cmd/toolboxd/`, `internal/cloudidentity/`, `internal/service/`, `sdk/*`, `docs/`
  - Verify: checker tests (bad chain, wrong PCR0/16/17/18/4, stale nonce); live KMS cross-sandbox Decrypt refused
- [ ] **T12 (P3, human: ~1.5 weeks / CC: ~2 days)** — M4 — `kubepod` driver with mTLS trust and lease fence
  - Surfaced by: Architecture — R5 (D8); outside review O8 → R17 (D17)
  - Files: `internal/runtime/kubepod/`, `cmd/toolboxd/`, `charts/aerolvm/`
  - Verify: client-go fake tests; kind with a gVisor RuntimeClass; partitioned-worker fence test
- [ ] **T13 (P2, human: ~2 weeks / CC: ~2 days)** — Discoverability — feature table, `GET /v1/runtimes`, SDK/CLI/MCP, create feedback, operator report, comparison docs
  - Surfaced by: owner request R21 (D23)
  - Files: `pkg/models/types.go`, `pkg/api/v1/routes.go`, `sdk/*`, `cmd/aerolvm/`, `internal/agentmcp/`, `internal/nodejoin/pod_preflight.go`, `charts/aerolvm/templates/NOTES.txt`, `docs/src/content/docs/choose-isolation.mdx`, `docs/src/content.config.ts`, `charts/aerolvm/EVIDENCE.md`
  - Verify: `go test ./pkg/api/v1/... ./pkg/models/...`; each SDK's test suite; the docs-table test; `make docs-build`

_Effort ratios assumed: architecture work ~5x, features ~30x, tests ~50x (human ÷ CC)._

### Unresolved decisions
None.

### Completion summary
- Step 0: Scope Challenge — scope accepted as-is (D3 kept every feature, one socket instead of two)
- Reality rows: 7/7 applicable rows emitted (`PLAN_REALITY: phase=eng rows=7/7 missing=none unverified=3 verdict=complete`), 3 unverified premises
- Architecture Review: 6 issues found (R1, R2, R3, R4, R5, R9)
- Code Quality Review: 1 issue found (R6)
- Test Review: diagram produced, 1 regression-contract gap identified (R8); every proposed path has a planned test
- Performance Review: 1 issue found (R7)
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 2 items proposed to user (D18 added; D19 built into M3 v1 instead), plus the pod mode entry refreshed (C3)
- Failure modes: 0 critical gaps flagged
- Owner requirement (2026-11-20): every new option is an add-on behind a setting (R18); follow-ups D21 (Nitro parked warm pool) and D22 (`privilegeMode` setting) decided
- Owner request (2026-11-20): discoverability designed as plan §11 and approved in full (D23); task T13
- Unresolved decisions: 0 in this review
- Outside voice: Codex (gpt-6-astra), completed, 8 findings (6 decided by the owner, 2 corrected as D4 carried work)
- Parallelization: 3 lanes, 2 parallel / 1 on trigger
- Lake Score: 1/7 = answers picking a 10/10 option / answers scored for Completeness (D21 and D22 differ in kind, not scored)

### Suppressed findings
None (no finding scored below 5).

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | not run on this plan (the K8s v2 CEO plan of 2026-11-10 was used as context) |
| Outside Review | Codex (gpt-6-astra), default-on plan review | Independent 2nd opinion | 1 | completed (issues_found) | 8 findings: 6 decided by the owner (D12–D17), 2 corrected as D4 carried work |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | ISSUES OPEN | 9 issues, 0 critical gaps (all resolved into accepted plan changes and tasks T1–T13); owner add-on requirement (R18, D21, D22) and discoverability (§11, D23) applied |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | not applicable (no UI) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | not run |

- **OUTSIDE COVERAGE:** Codex, phase plan-review, completed, 8 findings (O1 Critical; O2–O8 High).
- **CROSS-MODEL:** Claude (native) and Codex (gpt-6-astra) both flagged the helper hot swap (R1; O3, O6); Claude alone found the gate contract, rollout, KMS identity, pod-mode token, refusal alerts, regression contract and concurrency gaps (R2–R8); Codex alone found the M3 identity gaps (O1, O2), the BuildKit root path (O4), the confidential Stop contradiction (O5), the Firecracker snapshot upgrade (O7) and the pod-mode fence (O8).
- **VERDICT:** no review CLEAR yet; Eng Review found 9 issues, all decided and mapped to tasks — eng review required

NO UNRESOLVED DECISIONS
