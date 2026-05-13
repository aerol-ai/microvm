package daytona

import (
	"errors"
	"strings"
	"sync"
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

type metadataStore struct {
	mu     sync.RWMutex
	byID   map[string]sandboxMeta
	byName map[string]string
}

func newMetadataStore() *metadataStore {
	return &metadataStore{
		byID:   map[string]sandboxMeta{},
		byName: map[string]string{},
	}
}

func (m *metadataStore) nameInUse(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	m.mu.RLock()
	_, ok := m.byName[name]
	m.mu.RUnlock()
	return ok
}

func (m *metadataStore) resolve(idOrName string) string {
	trimmed := strings.TrimSpace(idOrName)
	m.mu.RLock()
	resolved, ok := m.byName[trimmed]
	m.mu.RUnlock()
	if ok {
		return resolved
	}
	return trimmed
}

func (m *metadataStore) get(id string) (sandboxMeta, bool) {
	m.mu.RLock()
	meta, ok := m.byID[id]
	m.mu.RUnlock()
	if !ok {
		return sandboxMeta{}, false
	}
	return cloneMeta(meta), true
}

func (m *metadataStore) upsert(id string, meta sandboxMeta) error {
	meta = cloneMeta(meta)
	meta.Name = strings.TrimSpace(meta.Name)
	if meta.Name == "" {
		meta.Name = id
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if existingID, ok := m.byName[meta.Name]; ok && existingID != id {
		return errNameConflict
	}

	if existing, ok := m.byID[id]; ok && existing.Name != "" && existing.Name != meta.Name {
		delete(m.byName, existing.Name)
	}

	m.byID[id] = cloneMeta(meta)
	m.byName[meta.Name] = id
	return nil
}

func (m *metadataStore) delete(id string) {
	m.mu.Lock()
	if existing, ok := m.byID[id]; ok && existing.Name != "" {
		delete(m.byName, existing.Name)
	}
	delete(m.byID, id)
	m.mu.Unlock()
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
