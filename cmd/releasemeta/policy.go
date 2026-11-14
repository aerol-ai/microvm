package main

// Per-release policy that no code can derive. Change these in the release
// PR that needs it; release.yml picks them up from the tagged tree.

// upgradeFromMin is the oldest release that may upgrade straight to a build
// of this tree. Raise it when the release removes something an older
// release's upgrade path relied on: the old-schema code path of a one-way
// migration that release finalized, an FSM op or cross-node format that
// only the intermediate release taught the cluster. `aerolvm upgrade plan`
// then prints the releases to step through.
const upgradeFromMin = "v0.6.11"

// hostSetupNeedsNetwork is true in a release whose install.sh host changes
// need packages or network access (plans/kubectl-style-cluster-ops.md §6.3
// step 7). An offline or --from rollout of such a release is refused at
// `upgrade plan`, before any node stops.
const hostSetupNeedsNetwork = false
