package daytona

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

var errNameConflict = errors.New("daytona sandbox name already in use")

// sandboxMeta is the in-memory shape the handlers manipulate. Some fields
// (Name, User, Labels, AutoStopInterval, AutoDeleteInterval) are derived
// from the native sandbox row at read time; the rest are facade-private
// echo-back state stored in sandbox_compat_state.state_json.
type sandboxMeta struct {
	Name                string
	Snapshot            *string
	User                string
	Labels              map[string]string
	Target              string
	NetworkAllowList    *string
	AutoStopInterval    *float32
	AutoArchiveInterval *float32
	AutoDeleteInterval  *float32
}

// compatBlob is the persisted JSON shape inside sandbox_compat_state.state_json
// for the Daytona facade. Only fields that have no native AerolVM equivalent
// live here — Name, Labels, User, and the auto-stop/destroy intervals are
// derived from the sandbox row instead. AutoArchiveInterval has no native
// equivalent (AerolVM has no archive concept) so it is stored opaquely.
type compatBlob struct {
	Snapshot            string  `json:"snapshot,omitempty"`
	Target              string  `json:"target,omitempty"`
	NetworkAllowList    string  `json:"network_allow_list,omitempty"`
	AutoArchiveInterval float32 `json:"auto_archive_interval_minutes,omitempty"`
}

func defaultSandboxMeta(sandbox *models.Sandbox) sandboxMeta {
	if sandbox == nil {
		return sandboxMeta{Labels: map[string]string{}}
	}
	return sandboxMetaFromNative(sandbox, compatBlob{})
}

// sandboxMetaFromNative builds a sandboxMeta from the native sandbox row
// plus the optional Daytona-private blob. Used by both the meta-present
// and meta-absent code paths so derived fields are computed in one place.
func sandboxMetaFromNative(sandbox *models.Sandbox, blob compatBlob) sandboxMeta {
	meta := sandboxMeta{
		Name:                firstNonEmpty(strings.TrimSpace(sandbox.Name), sandbox.ID),
		Snapshot:            emptyStringToPtr(blob.Snapshot),
		User:                strings.TrimSpace(sandbox.OSUser),
		Labels:              cloneStringMap(sandbox.Tags),
		Target:              strings.TrimSpace(blob.Target),
		NetworkAllowList:    emptyStringToPtr(blob.NetworkAllowList),
		AutoStopInterval:    durationMinutesPtr(sandbox.Lifecycle.StopIfIdleFor),
		AutoArchiveInterval: nonZeroFloatPtr(blob.AutoArchiveInterval),
		AutoDeleteInterval:  durationMinutesPtr(sandbox.Lifecycle.DestroyIfIdleFor),
	}
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	return meta
}

// sandboxMetaFromState rebuilds a sandboxMeta by unmarshalling the
// compat blob and combining it with the native sandbox row. nil sandbox
// would be a programming error — handlers always have one in hand.
func sandboxMetaFromState(state *models.SandboxCompatState, sandbox *models.Sandbox) (sandboxMeta, error) {
	if sandbox == nil {
		return sandboxMeta{Labels: map[string]string{}}, nil
	}
	if state == nil || strings.TrimSpace(state.StateJSON) == "" {
		return sandboxMetaFromNative(sandbox, compatBlob{}), nil
	}
	var blob compatBlob
	if err := json.Unmarshal([]byte(state.StateJSON), &blob); err != nil {
		return sandboxMeta{}, err
	}
	return sandboxMetaFromNative(sandbox, blob), nil
}

// sandboxMetaToState marshals just the facade-private bits into a JSON
// string suitable for sandbox_compat_state.state_json. Native fields
// (Name, Labels, User, lifecycle intervals) are written through the
// native sandbox row instead.
func sandboxMetaToState(meta sandboxMeta) (string, error) {
	blob := compatBlob{
		Snapshot:            strings.TrimSpace(valueOrEmpty(meta.Snapshot)),
		Target:              strings.TrimSpace(meta.Target),
		NetworkAllowList:    strings.TrimSpace(valueOrEmpty(meta.NetworkAllowList)),
		AutoArchiveInterval: float32Value(meta.AutoArchiveInterval),
	}
	encoded, err := json.Marshal(blob)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func cloneMeta(meta sandboxMeta) sandboxMeta {
	return sandboxMeta{
		Name:                meta.Name,
		Snapshot:            cloneStringPtr(meta.Snapshot),
		User:                meta.User,
		Labels:              cloneStringMap(meta.Labels),
		Target:              meta.Target,
		NetworkAllowList:    cloneStringPtr(meta.NetworkAllowList),
		AutoStopInterval:    cloneFloat32Ptr(meta.AutoStopInterval),
		AutoArchiveInterval: cloneFloat32Ptr(meta.AutoArchiveInterval),
		AutoDeleteInterval:  cloneFloat32Ptr(meta.AutoDeleteInterval),
	}
}

func emptyStringToPtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func cloneFloat32Ptr(value *float32) *float32 {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

// durationMinutesPtr is defined in handlers.go.

func nonZeroFloatPtr(value float32) *float32 {
	if value <= 0 {
		return nil
	}
	v := value
	return &v
}

func float32Value(value *float32) float32 {
	if value == nil {
		return 0
	}
	return *value
}
