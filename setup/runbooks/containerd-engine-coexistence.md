# Container engine coexistence (dockerd ↔ containerd)

Use this when flipping a host between `SB_CONTAINER_ENGINE=docker` and
`containerd`, or when both engines share one system containerd during a
drain window (`plans/containerd-engine.md` §7.6 / Phase 5).

## What stays separate

| Surface | dockerd | containerd engine |
|---|---|---|
| containerd namespace | `moby` (owned by dockerd) | `aerolvm` (sandboxd) |
| Image content store | dockerd graph driver | containerd content + snapshotter |
| Netrules chain | `AEROLVM-USER` (shared host iptables) | same chain name |
| Env flip | `SB_CONTAINER_ENGINE=docker` | `SB_CONTAINER_ENGINE=containerd` |

Sandboxes record their owning engine in the store. Flipping the host env
never migrates existing sandboxes — drain or destroy them on the old
engine before flipping.

## Disk math during drain

dockerd and the `aerolvm` namespace do **not** share image layers. While
both engines run the same images on one node, disk use roughly doubles
for those images. Watch:

```bash
df -h /
sudo du -sh /var/lib/docker /var/lib/containerd
```

Keep free space above the usual image-pull-storm headroom for the drain
window. Prefer draining one node at a time so the rest of the cluster
keeps serving.

## Flip procedure (operator)

1. Confirm CNI plugins exist (`/opt/cni/bin/bridge`, `host-local`,
   `loopback`) — `install.sh --with-containerd-engine` or Ansible
   `configure-ops.yml` when `container_engine: containerd`.
2. Confirm system containerd is up: `systemctl is-active containerd`.
3. Drain the node (existing Ansible drain / lifecycle playbook).
4. Set `container_engine: containerd` in `config/cluster.yml` (or
   `SB_CONTAINER_ENGINE=containerd` in the env file).
5. Apply ops config / restart sandboxd; check `/health` and capacity
   metrics for `ContainerEngine=containerd` (or Server-Timing `engine`).
6. Smoke: create → exec → destroy one sandbox; run
   `AEROL_SECURITY_SPEC_DIFF=1` when validating security parity.

Reverse the env to roll back to dockerd after draining containerd-owned
sandboxes. No image migration — registry-backed images re-pull; local-only
builds need an explicit rebuild.

## Verification

```bash
grep ^SB_CONTAINER_ENGINE= /etc/sandboxd/cluster.env /etc/sandboxd/sandboxd.env
sudo ctr -n aerolvm containers ls
sudo journalctl -u sandboxd --since "10 minutes ago" --no-pager \
  | grep -iE 'containerd|engine|netns|cni'
```

## Drill

On staging: flip one non-ingress node docker → containerd → docker, confirm
disk headroom, capacity engine tag, and that dockerd workloads on peers are
unaffected.
