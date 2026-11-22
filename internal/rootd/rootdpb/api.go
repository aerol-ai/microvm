package rootdpb

import (
	"errors"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// APIVersion is the newest API level this build speaks, as the agent and
// as the helper. Bump it at most once per release, and only in a release
// that adds to the API: then the helper one release back speaks at least
// APIVersion-1, and agent N keeps working with helper N-1 (eng review D5).
const APIVersion uint32 = 1

// MinHelperAPI is the oldest helper this agent works with: one release
// back. An older helper is refused whole, with a reason.
const MinHelperAPI = max(APIVersion-1, 1)

// ServicePrefix starts the full method name of every call in the helper's
// own API, at any version. The helper answers such a call it does not have
// with Unimplemented instead of handing it to the containerd gate, which
// would count a version skew as a hostile call.
const ServicePrefix = "/aerolvm.rootd."

// The features a helper can list in VersionResponse.features: each is the
// short name of a RootHelper call.
const (
	FeatureEnsureHost           = "EnsureHost"
	FeatureEnsureHostFiles      = "EnsureHostFiles"
	FeatureEnsureTaskFIFOs      = "EnsureTaskFIFOs"
	FeatureEnsureRunscConfig    = "EnsureRunscConfig"
	FeatureEnsureReadySocket    = "EnsureReadySocket"
	FeatureRemoveContainerFiles = "RemoveContainerFiles"
	FeatureEnsureHostNetwork    = "EnsureHostNetwork"
	FeatureRealizeNetns         = "RealizeNetns"
	FeatureRemoveNetns          = "RemoveNetns"
	FeatureDisableNetnsIPv6     = "DisableNetnsIPv6"
	FeatureNetnsAddrs           = "NetnsAddrs"
	FeatureSetNodeGuard         = "SetNodeGuard"
	FeatureSetEgressFloor       = "SetEgressFloor"
	FeatureSandboxRules         = "SandboxRules"
	FeaturePrepareSandbox       = "PrepareSandbox"
	FeatureReleaseSandbox       = "ReleaseSandbox"
	FeatureBridgeProbe          = "BridgeProbe"
	FeatureMatchProcess         = "MatchProcess"
	FeatureHostPort             = "HostPort"
	// External storage mounts (M1 PR 8).
	FeatureMountExternal       = "MountExternal"
	FeatureUnmountExternal     = "UnmountExternal"
	FeatureSweepExternalMounts = "SweepExternalMounts"
	// Platform volume reclaim on NFS (M1 PR 8).
	FeatureReclaimVolume = "ReclaimVolume"
)

// The parts of PrepareSandbox and ReleaseSandbox (VersionResponse.parts).
// A part joins a later release by name; a helper refuses a request that
// lists a part, or sets a field, it does not know, and the agent sends a
// part only when the handshake listed it, so a part is never skipped
// without a word on either side of a version skew.
const (
	// PartNetns: the slot's namespace (realized by PrepareSandbox, removed
	// by ReleaseSandbox).
	PartNetns = "netns"
	// PartFirewall: the create's host rules (PrepareSandbox), every rule
	// for the address (ReleaseSandbox).
	PartFirewall = "firewall"
	// PartCgroup: a started sandbox's group made the kernel's whole
	// out-of-memory choice (PrepareSandbox only, and alone; M1 PR 6). The
	// runtime removes the group with the task, so ReleaseSandbox has none.
	PartCgroup = "cgroup"
	// PartFiles: the files root opens for a container, in the helper's own
	// folders (PrepareSandbox, before the container is made and before
	// each start), and their removal (ReleaseSandbox, alone). Named by the
	// request's container_id; M1 PR 7.
	PartFiles = "files"
	// PartImageUser: the user a container's image runs as, read from the
	// image's own files in the container's snapshot (PrepareSandbox, with
	// the container's other parts; M1 PR 7).
	PartImageUser = "image_user"
	// PartDiskQuota: a hard limit on a container's writable layer
	// (PrepareSandbox, with the container's other parts, or alone for a
	// resize; M1 PR 7).
	PartDiskQuota = "disk_quota"
)

// Parts lists every part name above.
func Parts() []string {
	return []string{PartNetns, PartFirewall, PartCgroup, PartFiles, PartImageUser, PartDiskQuota}
}

// AnsweredTrailer is the trailer the helper's server puts on every call it
// handles, its own and the gate's. A failed call that carries it is the
// helper's answer (a refusal, or containerd's own error passed on); one
// without it failed between the agent and the helper. The agent's client
// marks only the second kind as the helper unavailable.
const AnsweredTrailer = "aerolvm-rootd-answered"

// Features lists every feature name above, for tests that must cover each.
func Features() []string {
	return []string{FeatureEnsureHost, FeatureEnsureHostFiles, FeatureEnsureTaskFIFOs,
		FeatureEnsureRunscConfig, FeatureEnsureReadySocket, FeatureRemoveContainerFiles,
		FeatureEnsureHostNetwork, FeatureRealizeNetns, FeatureRemoveNetns, FeatureDisableNetnsIPv6, FeatureNetnsAddrs,
		FeatureSetNodeGuard, FeatureSetEgressFloor, FeatureSandboxRules, FeaturePrepareSandbox, FeatureReleaseSandbox,
		FeatureBridgeProbe, FeatureMatchProcess, FeatureHostPort,
		FeatureMountExternal, FeatureUnmountExternal, FeatureSweepExternalMounts, FeatureReclaimVolume}
}

// ErrHelperUnavailable: the helper could not be reached or did not answer.
// internal/rootclient exports it as ErrUnavailable; it lives here so the
// HelperUnavailable detail can match it.
var ErrHelperUnavailable = errors.New("root helper unavailable")

// Error makes the detail an error, which is what containerd's error
// conversion (errgrpc.ToNative) keeps from a status's details.
func (*HelperUnavailable) Error() string { return ErrHelperUnavailable.Error() }

// Is matches ErrHelperUnavailable, so errors.Is holds on the error
// containerd's client returns.
func (*HelperUnavailable) Is(target error) bool { return target == ErrHelperUnavailable }

// ErrHelperUnsupported: the helper is older than the agent and lacks what
// it asked for. internal/rootclient exports it as ErrUnsupported.
var ErrHelperUnsupported = errors.New("root helper does not support this")

// Error is the reason, so it reaches the API's message.
func (d *HelperUnsupported) Error() string {
	if d.GetReason() == "" {
		return ErrHelperUnsupported.Error()
	}
	return d.GetReason()
}

// Is matches ErrHelperUnsupported.
func (*HelperUnsupported) Is(target error) bool { return target == ErrHelperUnsupported }

// ErrHelperRefused: the helper or its containerd gate refused the call; it
// broke the helper's rules. internal/rootclient exports it as ErrRefused.
var ErrHelperRefused = errors.New("root helper refused the call")

// Error names the reason, so the error containerd's client rebuilds from
// the status still says which rule.
func (d *HelperRefused) Error() string {
	if d.GetReason() == "" {
		return ErrHelperRefused.Error()
	}
	return ErrHelperRefused.Error() + " (" + d.GetReason() + ")"
}

// Is matches ErrHelperRefused.
func (*HelperRefused) Is(target error) bool { return target == ErrHelperRefused }

// Refused is the status the helper answers a refused call with: code and
// msg as before, and a HelperRefused detail carrying reason, which is how
// the agent's client tells a refusal from any other failure. msg is for
// logs; reason is what the agent counts and audits.
func Refused(code codes.Code, reason, msg string) error {
	st := status.New(code, msg)
	if withDetail, err := st.WithDetails(&HelperRefused{Reason: reason}); err == nil {
		st = withDetail
	}
	return st.Err()
}

// RefusalReason reads a refusal's reason from err's status: ok only when
// the status carries a HelperRefused detail, which only the helper adds.
func RefusalReason(err error) (reason string, ok bool) {
	st, isStatus := status.FromError(err)
	if !isStatus {
		return "", false
	}
	for _, d := range st.Details() {
		if r, isRefused := d.(*HelperRefused); isRefused {
			return r.GetReason(), true
		}
	}
	return "", false
}

// CallName is the short name of a gRPC method, "Service.Method"
// ("/containerd.services.tasks.v1.Tasks/Create" is "Tasks.Create"), the
// form the plan names calls in. A refusal's metric label and audit record
// use it, so it must stay one of a fixed set: a method that is not
// /<package>.<Service>/<Method> with plain identifiers is "other", and a
// bare word ("connect", rootd.MethodConnect) stays itself.
func CallName(fullMethod string) string {
	if word.MatchString(fullMethod) {
		return fullMethod
	}
	svc, method, ok := strings.Cut(strings.TrimPrefix(fullMethod, "/"), "/")
	svc = svc[strings.LastIndexByte(svc, '.')+1:]
	if !ok || !strings.HasPrefix(fullMethod, "/") || !ident.MatchString(svc) || !ident.MatchString(method) {
		return CallOther
	}
	return svc + "." + method
}

// CallOther is CallName's answer for a method it cannot name.
const CallOther = "other"

var (
	word  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	ident = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)
