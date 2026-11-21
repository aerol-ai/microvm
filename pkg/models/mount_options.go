package models

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// Mount tools run on the host as the daemon user (root on a VM install),
// outside every sandbox (pr-review.md §5). options.extra_args becomes
// mount-s3's argv and options.opts becomes mount's -o list, so a flag there
// is a flag of a root process: a log or cache directory makes it write files
// where the caller says, --profile or --ca-bundle makes it read the host's
// own credentials or trust store, a helper= or x-mount.* option makes mount
// run or create things. A deny list would miss the next such flag a tool
// release adds, so these are allow lists: each names flags that only tune
// how the storage is reached, read and written, and the value each takes.
// A flag that names a host path, opens a listener or an outbound telemetry
// stream, picks a credential or config source, or runs a command is not on
// them.
//
// rclone takes no flags from the caller, but its source and rclone_conf
// choose a backend and that backend's options, which reach as far: the
// local backend serves a host directory, sftp's ssh option runs a command.
// So rclone has an allow list of backends (mount_options_rclone.go).

// mountArgKind is the kind of value an allowed flag or option takes.
type mountArgKind int

const (
	mountArgNone  mountArgKind = iota // a bare flag: --allow-delete, nolock
	mountArgUint                      // decimal digits: --uid 1000, timeo=600
	mountArgOctal                     // a file mode: --dir-mode 0755
	mountArgEnum                      // one of a fixed list of words
	mountArgToken                     // a plain name: a region, a KMS key ARN
	mountArgURL                       // an http or https URL
	mountArgWord                      // any word not starting with -: only on the kept lists
)

// mountArg says what value one allowed flag takes. For mountArgUint, words
// lists the words it also accepts (--metadata-ttl indefinite); for
// mountArgEnum, the only words it accepts. sep, when set, lets the value be
// a list of those words (NFS sec=krb5:krb5i).
type mountArg struct {
	kind  mountArgKind
	words []string
	sep   string
}

// mountArgTTL is mount-s3's SECONDS|indefinite|minimal metadata TTL.
var mountArgTTL = mountArg{kind: mountArgUint, words: []string{"indefinite", "minimal"}}

// mountS3Flags is what options.extra_args may hold, from mount-s3's own
// flag list (mountpoint-s3 src/cli.rs). Left out on purpose: --cache,
// --log-directory/-l and --ca-bundle (host paths); --profile (the host's
// AWS profiles); --otlp-endpoint (sends telemetry where the caller says);
// --bind (picks the host's network interface); --cache-xz (a second bucket
// the host's credentials write to); --debug/-d, --debug-crt, --log-metrics,
// --no-log (logging is the operator's); --auto-unmount (spawns a fusermount
// helper); and --foreground and --prefix, which the adapter sets itself.
var mountS3Flags = map[string]mountArg{
	// Where the bucket is and how it is reached.
	"--region":                {kind: mountArgToken},
	"--endpoint-url":          {kind: mountArgURL},
	"--force-path-style":      {},
	"--transfer-acceleration": {},
	"--dual-stack":            {},
	"--requester-pays":        {},
	"--bucket-type":           {kind: mountArgEnum, words: []string{"general-purpose", "directory"}},
	"--expected-bucket-owner": {kind: mountArgUint},
	"--no-sign-request":       {},
	// How new objects are written.
	"--storage-class":      {kind: mountArgToken},
	"--sse":                {kind: mountArgEnum, words: []string{"aws:kms", "aws:kms:dsse", "AES256"}},
	"--sse-kms-key-id":     {kind: mountArgToken},
	"--upload-checksums":   {kind: mountArgEnum, words: []string{"crc32c", "crc64nvme", "off"}},
	"--infer-content-type": {},
	// What the sandbox may do with the files.
	"--read-only":          {},
	"--allow-delete":       {},
	"--allow-overwrite":    {},
	"--incremental-upload": {},
	"--allow-root":         {},
	"--allow-other":        {},
	"--uid":                {kind: mountArgUint},
	"--gid":                {kind: mountArgUint},
	"--dir-mode":           {kind: mountArgOctal},
	"--file-mode":          {kind: mountArgOctal},
	// Throughput, memory and in-memory metadata caching.
	"--maximum-throughput-gbps": {kind: mountArgUint},
	"--max-threads":             {kind: mountArgUint},
	"--memory-target":           {kind: mountArgUint},
	"--part-size":               {kind: mountArgUint},
	"--read-part-size":          {kind: mountArgUint},
	"--write-part-size":         {kind: mountArgUint},
	"--metadata-ttl":            mountArgTTL,
	"--negative-metadata-ttl":   mountArgTTL,
}

// mountNFSOptions is what options.opts may hold, from nfs(5) and the
// filesystem-independent options of mount(8). Left out on purpose: suid,
// dev and defaults (the adapter forces nosuid,nodev, see adapters.NFS);
// context=, fscontext=, defcontext=, rootcontext= (SELinux labels);
// helper=, x-mount.* and x-* (mount runs or creates things); loop, offset,
// bind, rbind, move, remount and the propagation flags (they act on other
// mounts or host files); user, users, owner, group; bg (forks a process
// that keeps retrying after mount returns); fsc (the host's FS-Cache);
// clientaddr, mounthost and xprtsec (callback address, a second host, the
// host's TLS identity).
var mountNFSOptions = func() map[string]mountArg {
	flags := []string{
		// Generic mount(8) options that change only how the share behaves.
		"ro", "rw", "sync", "async", "atime", "noatime", "diratime", "nodiratime",
		"relatime", "norelatime", "strictatime", "nostrictatime", "lazytime", "nolazytime",
		"exec", "noexec", "nosuid", "nodev", "nosymfollow",
		// fstab words mount ignores outside mount -a, accepted so options
		// pasted from an fstab line still work.
		"_netdev", "nofail",
		// NFS transport, failure handling, caching, locking and ACLs.
		"tcp", "udp", "rdma", "resvport", "noresvport",
		"soft", "hard", "softerr", "softreval", "nosoftreval", "intr", "nointr",
		"ac", "noac", "cto", "nocto", "sharecache", "nosharecache", "rdirplus", "nordirplus",
		"lock", "nolock", "acl", "noacl",
	}
	version := mountArg{kind: mountArgEnum, words: []string{"3", "4", "4.0", "4.1", "4.2"}}
	transport := mountArg{kind: mountArgEnum, words: []string{"tcp", "udp", "rdma", "tcp6", "udp6", "rdma6"}}
	number := mountArg{kind: mountArgUint}
	opts := map[string]mountArg{
		"vers": version, "nfsvers": version, "minorversion": number, "mountvers": number,
		"proto": transport, "mountproto": transport, "port": number, "mountport": number,
		"nconnect": number, "max_connect": number,
		"sec":   {kind: mountArgEnum, words: []string{"sys", "krb5", "krb5i", "krb5p"}, sep: ":"},
		"timeo": number, "retrans": number, "retry": number,
		"rsize": number, "wsize": number, "bsize": number, "namlen": number,
		"acregmin": number, "acregmax": number, "acdirmin": number, "acdirmax": number, "actimeo": number,
		"lookupcache": {kind: mountArgEnum, words: []string{"all", "none", "pos", "positive"}},
		"local_lock":  {kind: mountArgEnum, words: []string{"all", "flock", "posix", "none"}},
	}
	for _, f := range flags {
		opts[f] = mountArg{}
	}
	return opts
}()

// A sandbox still running when sandboxd restarts (the upgrade that brought
// these lists in, say) may hold a mount whose stored spec the lists now
// refuse. Its tool is already running, so tearing it down only breaks the
// sandbox's storage; the service keeps it as it runs and refuses the spec
// at the sandbox's next start (internal/service/mount_tool_options.go).
// That holds only for a refused flag that does no harm while the tool goes
// on running: the kept lists below, default deny like the lists above. Any
// other refusal means the running tool itself keeps reaching into the
// server (a folder it serves or writes, a command it runs again, the
// server's own credentials or network identity), and the mount is torn
// down. Every rclone refusal is one: rclone's lists are only about the
// storage the running tool reaches, and it re-reads key files and re-runs
// ssh on every reconnect.

// mountS3KeptFlags may stay in a running mount-s3's extra_args.
var mountS3KeptFlags = map[string]mountArg{
	// mount-s3 keeps its block cache in a folder it makes for itself under
	// this one, with names it chooses.
	"--cache":          {kind: mountArgWord},
	"--max-cache-size": {kind: mountArgUint},
	// How much it logs. With no --log-directory (refused, and not kept) the
	// output is the helper log sandboxd keeps and trims.
	"--debug": {}, "-d": {}, "--debug-crt": {}, "--log-metrics": {}, "--no-log": {},
	// Acts only when the mount ends.
	"--auto-unmount": {},
}

// mountNFSKeptOptions may stay in a running NFS mount's opts. The kernel
// holds the mount and no tool runs. suid and dev (defaults has both) are
// cleared on the host mount when it is taken over (mounts.adoptOne
// remounts it nosuid,nodev, and one that will not take them is not kept);
// the sandbox's bind keeps its flags until the next start, which these
// options never reach. bg, fg, auto and noauto only steer mounting, which
// is done; nouser is mount's default (only root unmounts); fsc uses the
// kernel's own cache, whose folder the operator set.
var mountNFSKeptOptions = []string{"defaults", "suid", "dev", "bg", "fg", "fsc", "auto", "noauto", "nouser"}

var (
	mountS3RunningFlags    = mergeMountArgs(mountS3Flags, mountS3KeptFlags)
	mountNFSRunningOptions = mergeMountArgs(mountNFSOptions, func() map[string]mountArg {
		kept := make(map[string]mountArg, len(mountNFSKeptOptions))
		for _, o := range mountNFSKeptOptions {
			kept[o] = mountArg{}
		}
		return kept
	}())
)

func mergeMountArgs(a, b map[string]mountArg) map[string]mountArg {
	out := maps.Clone(a)
	maps.Copy(out, b)
	return out
}

// mountValueOptions are the options keys an adapter passes as the value of
// a flag it sets itself (--region, --endpoint-url, --vfs-cache-mode=). Such
// a value cannot become a flag of its own there; checking it gives the
// caller a clear 400 instead of the tool's startup error.
var mountValueOptions = map[MountType][]struct {
	key string
	arg mountArg
}{
	MountTypeS3: {
		{"region", mountArg{kind: mountArgToken}},
		{"endpoint", mountArg{kind: mountArgURL}},
	},
	MountTypeRclone: {
		{"vfs_cache_mode", mountArg{kind: mountArgEnum, words: []string{"off", "minimal", "writes", "full"}}},
	},
}

// mountOptionsDocs points a refusal at the page that lists what is allowed.
const mountOptionsDocs = `see "Which flags are accepted" in the external storage docs`

// ValidateToolOptions refuses any mount-tool flag or option that is not on
// the allow list for the tool that would run it: options.extra_args for
// s3 (mount-s3), options.opts for nfs (mount -t nfs), the single-value
// options (region, endpoint, vfs_cache_mode), and for rclone the backend
// and backend options its source and every rclone_conf section name
// (validateRclone). extra_args and opts are
// refused on a type whose tool does not read them, so wiring either into
// another adapter later starts from "nothing allowed". An error names the
// flag or the word's position, never a value, as values can hold anything a
// caller pasted.
//
// The service holds every path that runs a mount tool to it: create, a
// failover rebuild, start, and the reconcile and WASM adopt after a
// restart, which never run a refused spec again: a mount still running
// is kept or torn down (ValidateRunningToolOptions), and the next start is
// refused (internal/service/mount_tool_options.go). Platform volumes'
// mounts are the operator's, checked once at daemon start instead
// (config.PlatformVolumesConfig.Validate).
func (m *MountSpec) ValidateToolOptions() error {
	return m.validateToolOptions(false)
}

// ValidateRunningToolOptions is the check a mount gets that is already
// running, with a spec ValidateToolOptions refuses, when sandboxd restarts.
// It passes when every refused flag is on the kept lists
// (mountS3KeptFlags, mountNFSKeptOptions), so the running mount may stay
// as it is until the sandbox next starts; an error names the first flag
// that may not, and the mount is torn down. extra_args and opts on a type
// whose tool does not read them pass: they never reached a tool.
func (m *MountSpec) ValidateRunningToolOptions() error {
	return m.validateToolOptions(true)
}

func (m *MountSpec) validateToolOptions(running bool) error {
	if m == nil {
		return errors.New("mount is nil")
	}
	s3Flags, nfsOpts := mountS3Flags, mountNFSOptions
	if running {
		s3Flags, nfsOpts = mountS3RunningFlags, mountNFSRunningOptions
	}
	if extra := m.Options["extra_args"]; strings.TrimSpace(extra) != "" {
		switch {
		case m.Type == MountTypeS3:
			if err := validateS3ExtraArgs(extra, s3Flags); err != nil {
				return err
			}
		case !running:
			return fmt.Errorf("options.extra_args is read only by s3 mounts, not %s", m.Type)
		}
	}
	if opts := m.Options["opts"]; opts != "" {
		switch {
		case m.Type == MountTypeNFS:
			if err := validateNFSOpts(opts, nfsOpts); err != nil {
				return err
			}
		case !running:
			return fmt.Errorf("options.opts is read only by nfs mounts, not %s", m.Type)
		}
	}
	for _, o := range mountValueOptions[m.Type] {
		if v := m.Options[o.key]; v != "" {
			if reason := o.arg.check(v); reason != "" {
				return fmt.Errorf("options.%s %s", o.key, reason)
			}
		}
	}
	if m.Type == MountTypeRclone {
		return validateRclone(m.Source, m.Credentials["rclone_conf"])
	}
	return nil
}

// validateS3ExtraArgs walks extra_args the way the S3 adapter splits it
// (whitespace) and mount-s3 parses it: --flag, --flag=value, or --flag
// followed by its value as the next word. flags is mountS3Flags, or
// mountS3RunningFlags for a running mount.
func validateS3ExtraArgs(extra string, flags map[string]mountArg) error {
	words := strings.Fields(extra)
	for i := 0; i < len(words); i++ {
		if !strings.HasPrefix(words[i], "-") {
			return fmt.Errorf("options.extra_args word %d is not a flag: each word must be an allowed mount-s3 flag or that flag's value (%s)", i+1, mountOptionsDocs)
		}
		// Short flags (-l, -d) and a bare "--" are not in the table, so
		// they are refused here too.
		name, value, hasValue := strings.Cut(words[i], "=")
		arg, ok := flags[name]
		if !ok {
			return fmt.Errorf("options.extra_args flag %q is not allowed for s3 mounts: mount-s3 runs on the server, so only flags that tune the mount are accepted (%s)", name, mountOptionsDocs)
		}
		if arg.kind == mountArgNone {
			if hasValue {
				return fmt.Errorf("options.extra_args flag %q takes no value", name)
			}
			continue
		}
		if !hasValue {
			if i+1 == len(words) {
				return fmt.Errorf("options.extra_args flag %q needs a value", name)
			}
			i++
			value = words[i]
		}
		if reason := arg.check(value); reason != "" {
			return fmt.Errorf("options.extra_args flag %q %s", name, reason)
		}
	}
	return nil
}

// validateNFSOpts checks the comma-separated -o list. The adapter hands
// the string to mount unchanged, so whitespace and quotes are refused
// outright: mount would read a quoted value as one value even across a
// comma, and that is how a second option hides inside the first. options
// is mountNFSOptions, or mountNFSRunningOptions for a running mount.
func validateNFSOpts(opts string, options map[string]mountArg) error {
	if strings.ContainsFunc(opts, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '"' || r == '\'' }) {
		return errors.New("options.opts must not contain spaces or quotes: give NFS options as name or name=value, separated by commas")
	}
	for _, entry := range strings.Split(opts, ",") {
		if entry == "" {
			continue // mount skips an empty entry, as in a trailing comma
		}
		name, value, hasValue := strings.Cut(entry, "=")
		arg, ok := options[name]
		if !ok {
			return fmt.Errorf("options.opts entry %q is not allowed for nfs mounts: mount runs on the server, so only NFS tuning options are accepted (%s)", name, mountOptionsDocs)
		}
		switch {
		case arg.kind == mountArgNone && hasValue:
			return fmt.Errorf("options.opts entry %q takes no value", name)
		case arg.kind != mountArgNone && !hasValue:
			return fmt.Errorf("options.opts entry %q needs a value", name)
		case arg.kind != mountArgNone:
			if reason := arg.check(value); reason != "" {
				return fmt.Errorf("options.opts entry %q %s", name, reason)
			}
		}
	}
	return nil
}

// check returns why v is not a value this flag takes, or "" when it is.
func (a mountArg) check(v string) string {
	switch a.kind {
	case mountArgUint:
		if isASCIIDigits(v) || slices.Contains(a.words, v) {
			return ""
		}
		if len(a.words) > 0 {
			return fmt.Sprintf("takes a whole number or one of: %s", strings.Join(a.words, ", "))
		}
		return "takes a whole number"
	case mountArgOctal:
		if v != "" && len(v) <= 4 && strings.Trim(v, "01234567") == "" {
			return ""
		}
		return "takes an octal file mode such as 0755"
	case mountArgEnum:
		parts := []string{v}
		if a.sep != "" {
			parts = strings.Split(v, a.sep)
		}
		for _, p := range parts {
			if !slices.Contains(a.words, p) {
				return fmt.Sprintf("takes one of: %s", strings.Join(a.words, ", "))
			}
		}
		return ""
	case mountArgToken:
		if isMountToken(v) {
			return ""
		}
		return "takes a plain name: letters, digits and . _ : / - only, not starting with -"
	case mountArgURL:
		u, err := url.Parse(v)
		if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && !strings.ContainsFunc(v, unicode.IsSpace) {
			return ""
		}
		return "takes an http or https URL with no user name or password"
	case mountArgWord:
		if v != "" && !strings.HasPrefix(v, "-") {
			return ""
		}
		return "takes a value that does not start with -"
	default:
		return "takes no value"
	}
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isMountToken is the value shape of a region, storage class or KMS key
// ARN (arn:aws:kms:us-east-1:111122223333:key/abc). It is never read as a
// path by the flags that take it.
func isMountToken(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == ':', r == '/', r == '-':
		default:
			return false
		}
	}
	return true
}
