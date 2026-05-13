package daytona

import (
	"errors"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

var errNameConflict = errors.New("daytona sandbox name already in use")

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

func defaultSandboxMeta(sandbox *models.Sandbox) sandboxMeta {
	if sandbox == nil {
		return sandboxMeta{Labels: map[string]string{}}
	}
	return sandboxMeta{
		Name:   sandbox.ID,
		User:   sandbox.OSUser,
		Labels: map[string]string{},
	}
}

func sandboxMetaFromStored(meta *models.DaytonaSandboxMetadata, sandbox *models.Sandbox) sandboxMeta {
	if meta == nil {
		return defaultSandboxMeta(sandbox)
	}
	fallback := defaultSandboxMeta(sandbox)
	return sandboxMeta{
		Name:                firstNonEmpty(strings.TrimSpace(meta.Name), fallback.Name),
		Snapshot:            emptyStringToPtr(meta.Snapshot),
		User:                firstNonEmpty(strings.TrimSpace(meta.User), fallback.User),
		Labels:              cloneStringMap(meta.Labels),
		Target:              strings.TrimSpace(meta.Target),
		NetworkAllowList:    emptyStringToPtr(meta.NetworkAllowList),
		AutoStopInterval:    cloneFloat32Ptr(meta.AutoStopIntervalMinutes),
		AutoArchiveInterval: cloneFloat32Ptr(meta.AutoArchiveIntervalMinutes),
		AutoDeleteInterval:  cloneFloat32Ptr(meta.AutoDeleteIntervalMinutes),
	}
}

func sandboxMetaToStored(sandboxID string, meta sandboxMeta) models.DaytonaSandboxMetadata {
	name := strings.TrimSpace(meta.Name)
	if name == "" {
		name = strings.TrimSpace(sandboxID)
	}
	return models.DaytonaSandboxMetadata{
		SandboxID:                  strings.TrimSpace(sandboxID),
		Name:                       name,
		Snapshot:                   strings.TrimSpace(valueOrEmpty(meta.Snapshot)),
		User:                       strings.TrimSpace(meta.User),
		Labels:                     cloneStringMap(meta.Labels),
		Target:                     strings.TrimSpace(meta.Target),
		NetworkAllowList:           strings.TrimSpace(valueOrEmpty(meta.NetworkAllowList)),
		AutoStopIntervalMinutes:    cloneFloat32Ptr(meta.AutoStopInterval),
		AutoArchiveIntervalMinutes: cloneFloat32Ptr(meta.AutoArchiveInterval),
		AutoDeleteIntervalMinutes:  cloneFloat32Ptr(meta.AutoDeleteInterval),
	}
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
