package types

// File event types a watch reports.
const (
	FileEventCreate = "create"
	FileEventWrite  = "write"
	FileEventRemove = "remove"
	// FileEventRename names the old path; the new path arrives as a create.
	FileEventRename = "rename"
	FileEventChmod  = "chmod"
	// FileEventOverflow means events were lost. List the folder again to
	// catch up. Reason says why.
	FileEventOverflow = "overflow"
)

// Overflow reasons.
const (
	// WatchOverflowKernelQueue: the sandbox kernel's event queue overflowed.
	WatchOverflowKernelQueue = "kernel_queue"
	// WatchOverflowEventBuffer: more events than the agent holds between two
	// sends (about 4096 in 250 ms).
	WatchOverflowEventBuffer = "event_buffer"
	// WatchOverflowWatchLimit: a folder could not be watched because the
	// sandbox's watch limit was reached; Path names it.
	WatchOverflowWatchLimit = "watch_limit"
)

// FileEvent is one change a file watch reports.
type FileEvent struct {
	// Type is one of the FileEvent* constants. Treat an unknown type as a
	// reason to list the folder again.
	Type string `json:"type"`
	// Path is absolute. It is empty for some overflow events.
	Path  string `json:"path,omitempty"`
	IsDir bool   `json:"is_dir,omitempty"`
	// Reason is set on overflow events: one of the WatchOverflow* constants.
	Reason string `json:"reason,omitempty"`
}

// WatchOptions configures a file watch.
type WatchOptions struct {
	// Recursive also watches every folder below the path, including new
	// ones as they appear.
	Recursive bool
	// OnEvent is called once per event, in order, on the watch's reader
	// goroutine. Keep it quick: events wait while it runs.
	OnEvent func(FileEvent)
}
