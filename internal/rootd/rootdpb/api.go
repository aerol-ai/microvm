package rootdpb

import "errors"

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
	FeatureEnsureHost = "EnsureHost"
)

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
