package main

// envd_watch.go serves E2B's four envd watcher calls (filesystem.proto:
// WatchDir, CreateWatcher, GetWatcherEvents, RemoveWatcher) from the same
// watcher as GET /files/watch, with the same runtime gate (plan F5, B3).
//
// E2B has no overflow event. Rather than drop events without a word, a
// watch that loses events ends with a resource_exhausted error: WatchDir
// closes its stream with it, and GetWatcherEvents answers it once and
// removes the watcher. The caller watches again and re-lists.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var envdEventTypes = map[string]string{
	watchEventCreate: "EVENT_TYPE_CREATE",
	watchEventWrite:  "EVENT_TYPE_WRITE",
	watchEventRemove: "EVENT_TYPE_REMOVE",
	watchEventRename: "EVENT_TYPE_RENAME",
	watchEventChmod:  "EVENT_TYPE_CHMOD",
}

const envdWatchOverflowMsg = "file events were lost (the watch overflowed); watch the folder again and list it to catch up"

// envdWatchRequest is WatchDirRequest and CreateWatcherRequest. Connect's
// JSON clients send camelCase field names, protojson also accepts the proto
// names, so both spellings are read. allow_network_mounts is accepted and
// ignored: inotify simply sees no remote changes on a network mount.
type envdWatchRequest struct {
	Path              string `json:"path"`
	Recursive         bool   `json:"recursive"`
	IncludeEntry      bool   `json:"includeEntry"`
	IncludeEntryProto bool   `json:"include_entry"`
}

func (r envdWatchRequest) includeEntry() bool { return r.IncludeEntry || r.IncludeEntryProto }

type envdWatcherIDRequest struct {
	WatcherID      string `json:"watcherId"`
	WatcherIDProto string `json:"watcher_id"`
}

func (r envdWatcherIDRequest) id() string {
	if r.WatcherID != "" {
		return strings.TrimSpace(r.WatcherID)
	}
	return strings.TrimSpace(r.WatcherIDProto)
}

type envdFilesystemEvent struct {
	Name  string         `json:"name"`
	Type  string         `json:"type"`
	Entry *envdEntryInfo `json:"entry,omitempty"`
}

// envdWatchDirResponse is WatchDirResponse: a oneof, so exactly one field.
type envdWatchDirResponse struct {
	Start      *struct{}            `json:"start,omitempty"`
	Filesystem *envdFilesystemEvent `json:"filesystem,omitempty"`
	Keepalive  *struct{}            `json:"keepalive,omitempty"`
}

type envdCreateWatcherResponse struct {
	WatcherID string `json:"watcherId"`
}

type envdGetWatcherEventsResponse struct {
	Events []envdFilesystemEvent `json:"events"`
}

// envdWatchEvents turns a batch into E2B events, named relative to the
// watched folder as E2B's envd names them. lost reports an overflow in the
// batch; the events before it are still returned.
func envdWatchEvents(root string, batch []watchEvent, includeEntry bool) (out []envdFilesystemEvent, lost bool) {
	out = make([]envdFilesystemEvent, 0, len(batch))
	for _, ev := range batch {
		if ev.Type == watchEventOverflow {
			return out, true
		}
		name, err := filepath.Rel(root, ev.Path)
		if err != nil {
			name = ev.Path
		}
		item := envdFilesystemEvent{Name: name, Type: envdEventTypes[ev.Type]}
		// Remove and rename name a path that no longer holds the entry.
		if includeEntry && ev.Type != watchEventRemove && ev.Type != watchEventRename {
			if entry, err := buildEnvdEntryInfo(ev.Path); err == nil {
				item.Entry = &entry
			}
		}
		out = append(out, item)
	}
	return out, false
}

// writeEnvdStreamError ends a Connect server stream with an error.
func writeEnvdStreamError(w http.ResponseWriter, code, message string) error {
	return writeConnectEnvelope(w, connectFlagEndStream, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

// handleEnvdWatchDir is the streaming WatchDir.
func (s *server) handleEnvdWatchDir(w http.ResponseWriter, r *http.Request) {
	if !fileWatchAllowed() {
		writeEnvdError(w, http.StatusNotImplemented, fileWatchUnsupportedMsg)
		return
	}
	var req envdWatchRequest
	if err := readConnectJSONRequest(r, &req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	fw, werr := openFileWatch(req.Path, req.Recursive)
	if werr != nil {
		writeEnvdError(w, werr.status, werr.msg)
		return
	}
	defer fw.close()

	stream := startConnectJSONStream(w)
	if err := stream.Send(envdWatchDirResponse{Start: &struct{}{}}); err != nil {
		return
	}
	keepalive := newKeepaliveTicker(r)
	if keepalive != nil {
		defer keepalive.Stop()
	}
	tick, stopTick := watchTickerFn(watchFlushInterval)
	defer stopTick()
	// send flushes the batch; done reports the stream has ended.
	send := func() (done bool) {
		events, lost := envdWatchEvents(fw.root, fw.batch.take(), req.includeEntry())
		for i := range events {
			if err := stream.Send(envdWatchDirResponse{Filesystem: &events[i]}); err != nil {
				return true
			}
		}
		if lost {
			_ = writeEnvdStreamError(w, "resource_exhausted", envdWatchOverflowMsg)
			return true
		}
		return false
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-fw.watcher.Done():
			if !send() {
				_ = stream.End()
			}
			return
		case <-tick:
			if send() {
				return
			}
		case <-keepaliveChan(keepalive):
			if err := stream.Send(envdWatchDirResponse{Keepalive: &struct{}{}}); err != nil {
				return
			}
		}
	}
}

// envdPollWatcher is a CreateWatcher watch, read by GetWatcherEvents.
type envdPollWatcher struct {
	fw           *fileWatch
	includeEntry bool
	idle         *time.Timer
}

// envdPollRegistry holds the polled watchers. A client that never calls
// RemoveWatcher would otherwise hold its inotify instance and stream slot
// until toolboxd exits, so a watcher nobody polls for envdPollIdleTTL is
// removed.
type envdPollRegistry struct {
	mu   sync.Mutex
	byID map[string]*envdPollWatcher
}

var (
	envdPollWatchers = &envdPollRegistry{byID: map[string]*envdPollWatcher{}}
	envdPollIdleTTL  = 10 * time.Minute
)

func (reg *envdPollRegistry) add(fw *fileWatch, includeEntry bool) string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	pw := &envdPollWatcher{fw: fw, includeEntry: includeEntry}
	reg.mu.Lock()
	reg.byID[id] = pw
	pw.idle = time.AfterFunc(envdPollIdleTTL, func() { reg.remove(id) })
	reg.mu.Unlock()
	return id
}

// get returns the watcher and restarts its idle clock.
func (reg *envdPollRegistry) get(id string) (*envdPollWatcher, bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	pw, ok := reg.byID[id]
	if ok {
		pw.idle.Reset(envdPollIdleTTL)
	}
	return pw, ok
}

func (reg *envdPollRegistry) remove(id string) {
	reg.mu.Lock()
	pw, ok := reg.byID[id]
	delete(reg.byID, id)
	reg.mu.Unlock()
	if ok {
		pw.idle.Stop()
		pw.fw.close()
	}
}

func (reg *envdPollRegistry) count() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return len(reg.byID)
}

func (s *server) handleEnvdCreateWatcher(w http.ResponseWriter, r *http.Request) {
	if !fileWatchAllowed() {
		writeEnvdError(w, http.StatusNotImplemented, fileWatchUnsupportedMsg)
		return
	}
	var req envdWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	fw, werr := openFileWatch(req.Path, req.Recursive)
	if werr != nil {
		writeEnvdError(w, werr.status, werr.msg)
		return
	}
	writeJSON(w, http.StatusOK, envdCreateWatcherResponse{WatcherID: envdPollWatchers.add(fw, req.includeEntry())})
}

func (s *server) handleEnvdGetWatcherEvents(w http.ResponseWriter, r *http.Request) {
	if !fileWatchAllowed() {
		writeEnvdError(w, http.StatusNotImplemented, fileWatchUnsupportedMsg)
		return
	}
	var req envdWatcherIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := req.id()
	pw, ok := envdPollWatchers.get(id)
	if !ok {
		writeEnvdError(w, http.StatusNotFound, "watcher not found")
		return
	}
	// Read Done before taking the batch: a watch that ended has added its
	// last events by the time Done closes, so none are left behind.
	ended := false
	select {
	case <-pw.fw.watcher.Done():
		ended = true
	default:
	}
	events, lost := envdWatchEvents(pw.fw.root, pw.fw.batch.take(), pw.includeEntry)
	if lost {
		envdPollWatchers.remove(id)
		writeEnvdError(w, http.StatusTooManyRequests, envdWatchOverflowMsg)
		return
	}
	if ended {
		// The folder is gone: this answer carries its last events, and the
		// watcher goes with it.
		envdPollWatchers.remove(id)
	}
	writeJSON(w, http.StatusOK, envdGetWatcherEventsResponse{Events: events})
}

// handleEnvdRemoveWatcher succeeds for an unknown id too, so a retried
// remove whose first answer was lost is not an error.
func (s *server) handleEnvdRemoveWatcher(w http.ResponseWriter, r *http.Request) {
	if !fileWatchAllowed() {
		writeEnvdError(w, http.StatusNotImplemented, fileWatchUnsupportedMsg)
		return
	}
	var req envdWatcherIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	envdPollWatchers.remove(req.id())
	writeJSON(w, http.StatusOK, envdEmptyResponse{})
}
