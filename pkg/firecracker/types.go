package firecracker

// These types mirror the Firecracker API schema fields we actually use.
// Anything Firecracker exposes that we don't drive — MMDS, balloon, entropy
// device internals — is intentionally omitted to keep the types small and
// to keep us honest about which surface we depend on. Add a field when a
// driver path actually needs it; do not pre-populate from the swagger.

// InstanceInfo is the GET / response. The runtime driver uses State to
// distinguish "Not started" / "Running" / "Paused" without re-deriving from
// process signals -- useful as a sanity check before issuing VMStateResumed.
type InstanceInfo struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// VmmVersion lets the driver fail-fast when a snapshot was taken on a
	// different Firecracker build than the one trying to load it; mismatch
	// is one of the top causes of mysterious snapshot-load failures
	// (see plans/snapshot-clone-fast-boot.md §Operational concerns #6).
	VmmVersion string `json:"vmm_version,omitempty"`
	AppName    string `json:"app_name,omitempty"`
}

// MachineConfig is the PUT /machine-config request. Memory is in MiB,
// matching Firecracker's wire shape (do not multiply by 1024×1024 here).
// SMT defaults false; hugepages are off by default but flipped on for
// template VMs so clones can share huge pages with the page cache.
type MachineConfig struct {
	VcpuCount       int    `json:"vcpu_count"`
	MemSizeMib      int    `json:"mem_size_mib"`
	SMT             bool   `json:"smt,omitempty"`
	TrackDirtyPages bool   `json:"track_dirty_pages,omitempty"`
	HugePages       string `json:"huge_pages,omitempty"`
}

// BootSource is the PUT /boot-source request for cold-boot VMMs. The
// kernel_image_path must be readable by the (possibly jailer-chrooted)
// firecracker process; the daemon resolves it ahead of time.
//
// BootArgs is the kernel command line. Our template VMs use:
//
//	console=ttyS0 reboot=k panic=1 pci=off nomodules \
//	  init=/usr/local/bin/toolboxd-init quiet
//
// The init binary is the toolbox agent's pre-snapshot wrapper that brings
// the vsock listener up before the snapshot is taken; see cmd/toolboxd/.
type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
	InitrdPath      string `json:"initrd_path,omitempty"`
}

// Drive attaches a block device. PathOnHost is the file or block-device
// path; IsRootDevice and IsReadOnly carry the usual semantics. RateLimiter
// is omitted from the type — we don't throttle template I/O today and
// surfacing the nested rate-limiter shape would bloat this type for no
// gain. Add it when an actual driver path needs it.
type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
	// CacheType: "Unsafe" or "Writeback". Default Unsafe matches the
	// Firecracker default. Writeback is required for snapshot-safe
	// overlays — the daemon sets it explicitly on per-sandbox overlays.
	CacheType string `json:"cache_type,omitempty"`
}

// DrivePatch is the PATCH /drives/{id} body. host_dev_path is the only
// mutable field today (the snapshot-clone overlay rebind path). Wire name
// is path_on_host — keep the JSON tag honest.
type DrivePatch struct {
	DriveID    string `json:"drive_id"`
	PathOnHost string `json:"path_on_host,omitempty"`
}

// NetworkInterface attaches a TAP device. HostDevName is the host-visible
// TAP name (e.g. "fc-tap-<sandbox-id-prefix>"); GuestMAC is what the guest
// sees on eth0 — fixing it per-sandbox lets the host-side DHCP/static-IP
// machinery key off MAC. RX/TX rate limiters are intentionally omitted for
// the same reason as Drive's: add when needed.
type NetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
	GuestMAC    string `json:"guest_mac,omitempty"`
}

// NetworkInterfacePatch is the PATCH /network-interfaces/{id} body. Firecracker
// v1.15 rejects host_dev_name on this endpoint, so current snapshot restore
// rebinding must use SnapshotLoad.NetworkOverrides. HostDevName remains here
// only for older API compatibility and tests that exercise the raw client.
type NetworkInterfacePatch struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name,omitempty"`
}

// Vsock attaches a virtio-vsock device. UDSPath is the listen-side UDS on
// the host: in-guest connect(CID=2, port=N) becomes a connection accepted
// at <UDSPath>_<N>. GuestCID is the guest's own context ID (must be >= 3
// per the virtio spec; CIDs 0–2 are reserved). The daemon allocates GuestCID
// from a SQLite pool — see internal/store/vsock_cids.
type Vsock struct {
	GuestCID int    `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// Logger attaches a file-backed logger. Optional; useful for capturing
// Firecracker's own diagnostic output (boot errors, snapshot fault messages)
// alongside the VMM process group's stderr.
type Logger struct {
	LogPath string `json:"log_path"`
	Level   string `json:"level,omitempty"`
	// ShowLevel / ShowLogOrigin are debugging fields; we leave them off in
	// production runs. Surface them in tests if needed.
}

// Action types Firecracker accepts on PUT /actions. Pause and Resume are
// intentionally not here: Firecracker v1.15 exposes those through PATCH /vm,
// not the action endpoint.
const (
	ActionInstanceStart = "InstanceStart"
)

// Action is the PUT /actions body. ActionType is one of the constants
// above.
type Action struct {
	ActionType string `json:"action_type"`
}

// VM states accepted by PATCH /vm. Firecracker uses this endpoint for
// Paused/Resumed transitions, especially around snapshot create/load.
const (
	VMStatePaused  = "Paused"
	VMStateResumed = "Resumed"
)

// VM is the PATCH /vm body.
type VM struct {
	State string `json:"state"`
}

// SnapshotCreate is the PUT /snapshot/create body. SnapshotType=Full is
// what template builds use; diff snapshots are an internal property of
// LoadSnapshot via EnableDiffSnapshots and do not flow through this type.
// Paths are host-side absolute paths (jailer chroot already resolved by
// the runtime driver).
type SnapshotCreate struct {
	SnapshotType string `json:"snapshot_type,omitempty"`
	SnapshotPath string `json:"snapshot_path"`
	MemFilePath  string `json:"mem_file_path"`
	Version      string `json:"version,omitempty"`
}

// SnapshotLoad is the PUT /snapshot/load body. EnableDiffSnapshots=true is
// the load-time flag that gives us per-clone CoW: the memory file stays
// mmap'd read-only and per-VMM writes go to a dirty bitmap. ResumeVM=false
// keeps the clone paused so the daemon can rebind the per-sandbox overlay
// before issuing PATCH /vm state=Resumed. Per-sandbox TAP rebinding is part
// of the load request itself via NetworkOverrides.
type SnapshotLoad struct {
	SnapshotPath        string            `json:"snapshot_path"`
	MemBackend          *MemoryBackend    `json:"mem_backend,omitempty"`
	EnableDiffSnapshots bool              `json:"enable_diff_snapshots,omitempty"`
	ResumeVM            bool              `json:"resume_vm,omitempty"`
	NetworkOverrides    []NetworkOverride `json:"network_overrides,omitempty"`
}

// NetworkOverride is one entry in SnapshotLoad.network_overrides. Firecracker
// applies these while restoring device state from the snapshot, before the VM
// is resumed.
type NetworkOverride struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
}

// MemoryBackend selects how Firecracker loads the snapshot memory file.
// BackendType "File" plus a file path is what we use; "Uffd" (userfaultfd)
// is a future axis for lazy fault-handler-driven page-in.
type MemoryBackend struct {
	BackendType string `json:"backend_type"`
	BackendPath string `json:"backend_path"`
}
