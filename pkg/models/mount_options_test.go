package models

import (
	"strings"
	"testing"
)

// Mount tools run as root on the host, so options.extra_args (mount-s3) and
// options.opts (mount -t nfs) are allow lists. Every accepted case is a
// flag that only tunes the mount; every refused case names a host path,
// opens a listener or outbound stream, picks a credential or config source,
// runs a command, or is a shape the tool would read some other way.
func TestMountSpecValidateToolOptions(t *testing.T) {
	s3 := func(opts map[string]string) MountSpec {
		return MountSpec{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: opts}
	}
	nfs := func(opts string) MountSpec {
		return MountSpec{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"opts": opts}}
	}
	rclone := func(opts map[string]string) MountSpec {
		return MountSpec{Type: MountTypeRclone, Source: "remote:path", Target: "/d", Options: opts,
			Credentials: map[string]string{"rclone_conf": "[remote]\ntype = s3\n"}}
	}
	sshfs := func(opts map[string]string) MountSpec {
		return MountSpec{Type: MountTypeSSHFS, Source: "u@h:/x", Target: "/d", Options: opts}
	}
	extra := func(args string) MountSpec { return s3(map[string]string{"extra_args": args}) }

	accepted := []struct {
		name string
		m    MountSpec
	}{
		// s3 (mount-s3): flags the adapter tests and the docs use, in both
		// value forms.
		{"s3 no options", s3(nil)},
		{"s3 adapter test flags", extra("--allow-delete --uid 1000")},
		{"s3 flag=value form", extra("--uid=1000 --gid=1000 --dir-mode=0755 --file-mode=0644")},
		{"s3 mount behavior", extra("--allow-delete --allow-overwrite --incremental-upload --allow-other --read-only")},
		{"s3 allow root", extra("--allow-root")},
		{"s3 bucket access", extra("--force-path-style --transfer-acceleration --dual-stack --requester-pays --no-sign-request --bucket-type general-purpose")},
		{"s3 writes", extra("--sse aws:kms --sse-kms-key-id arn:aws:kms:us-east-1:111122223333:key/abc-123 --storage-class STANDARD_IA --upload-checksums=off --infer-content-type")},
		{"s3 owner", extra("--expected-bucket-owner 111122223333")},
		{"s3 throughput", extra("--maximum-throughput-gbps 10 --max-threads=32 --memory-target 2048 --read-part-size 8388608 --write-part-size=16777216")},
		{"s3 part size", extra("--part-size 8388608")},
		{"s3 metadata ttl", extra("--metadata-ttl indefinite --negative-metadata-ttl=60")},
		{"s3 region and endpoint flags", extra("--region us-east-1 --endpoint-url=https://s3.example:9000/x")},
		{"s3 extra whitespace", extra("  --allow-delete \t --uid  1000 ")},
		{"s3 blank extra_args", extra("   ")},
		{"s3 region and endpoint options", s3(map[string]string{"region": "eu-west-1", "endpoint": "http://minio.local:9000"})},
		// nfs (mount -t nfs): docs, adapter tests, platform-volume config
		// and a typical EFS line.
		{"nfs docs default", nfs("rw")},
		{"nfs adapter test", nfs("rw,vers=4")},
		{"nfs platform volume", nfs("vers=4.1")},
		{"nfs krb5", nfs("vers=4.1,sec=krb5,hard,timeo=600,nolock")},
		{"nfs sec list", nfs("sec=krb5:krb5i:krb5p")},
		{"nfs efs fstab line", nfs("nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport,_netdev")},
		{"nfs tuning", nfs("proto=tcp,port=2049,nconnect=4,actimeo=30,lookupcache=positive,local_lock=none,noatime,nosuid,nodev,noexec")},
		{"nfs v3", nfs("nfsvers=3,mountproto=udp,mountport=20048,mountvers=3,nolock,noacl,nordirplus")},
		{"nfs trailing comma", nfs("ro,")},
		{"nfs empty opts", nfs("")},
		// rclone takes one value option; sshfs takes none.
		{"rclone cache mode", rclone(map[string]string{"vfs_cache_mode": "full"})},
		{"rclone no options", rclone(nil)},
		{"sshfs no options", sshfs(nil)},
		{"unrelated option key", sshfs(map[string]string{"note": "kept as is"})},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := tc.m.ValidateToolOptions(); err != nil {
				t.Fatalf("ValidateToolOptions(%+v) = %v, want accepted", tc.m.Options, err)
			}
		})
	}

	refused := []struct {
		name string
		m    MountSpec
		want string
	}{
		// s3: a flag that names a host path, in both value forms.
		{"s3 cache dir", extra("--cache /var/cache"), `flag "--cache" is not allowed`},
		{"s3 cache dir = form", extra("--allow-delete --cache=/etc"), `flag "--cache" is not allowed`},
		{"s3 log directory", extra("--log-directory /etc/cron.d"), `flag "--log-directory" is not allowed`},
		{"s3 log directory = form", extra("--log-directory=/root/.ssh"), `flag "--log-directory" is not allowed`},
		{"s3 log directory short", extra("-l /tmp/x"), `flag "-l" is not allowed`},
		{"s3 ca bundle", extra("--ca-bundle /tmp/evil.pem"), `flag "--ca-bundle" is not allowed`},
		// s3: credential or config source, outbound stream, interface,
		// second bucket, logging, helper process, adapter-owned flags.
		{"s3 profile", extra("--profile default"), `flag "--profile" is not allowed`},
		{"s3 otlp endpoint", extra("--otlp-endpoint=http://attacker:4318"), `flag "--otlp-endpoint" is not allowed`},
		{"s3 bind", extra("--bind eth1"), `flag "--bind" is not allowed`},
		{"s3 cache-xz", extra("--cache-xz other-bucket"), `flag "--cache-xz" is not allowed`},
		{"s3 debug", extra("--debug"), `flag "--debug" is not allowed`},
		{"s3 debug short", extra("-d"), `flag "-d" is not allowed`},
		{"s3 debug crt", extra("--debug-crt"), `flag "--debug-crt" is not allowed`},
		{"s3 auto unmount", extra("--auto-unmount"), `flag "--auto-unmount" is not allowed`},
		{"s3 foreground", extra("--foreground"), `flag "--foreground" is not allowed`},
		{"s3 prefix", extra("--prefix other/"), `flag "--prefix" is not allowed`},
		{"s3 unknown", extra("--future-flag"), `flag "--future-flag" is not allowed`},
		{"s3 end of options", extra("-- other-bucket /etc"), `flag "--" is not allowed`},
		// s3: words that are not flags, and malformed values.
		{"s3 bare word", extra("--allow-delete /etc"), "word 2 is not a flag"},
		{"s3 positional first", extra("other-bucket"), "word 1 is not a flag"},
		{"s3 bare flag with value", extra("--allow-delete=yes"), `flag "--allow-delete" takes no value`},
		{"s3 value missing", extra("--allow-delete --uid"), `flag "--uid" needs a value`},
		{"s3 value is a flag", extra("--region --log-directory=/tmp"), `flag "--region" takes a plain name`},
		{"s3 uid not a number", extra("--uid=root"), `flag "--uid" takes a whole number`},
		{"s3 mode not octal", extra("--dir-mode 0999"), `flag "--dir-mode" takes an octal file mode`},
		{"s3 mode too long", extra("--file-mode=07777"), `flag "--file-mode" takes an octal file mode`},
		{"s3 sse unknown", extra("--sse rot13"), `flag "--sse" takes one of`},
		{"s3 ttl word", extra("--metadata-ttl forever"), `flag "--metadata-ttl" takes a whole number or one of`},
		{"s3 kms key with shell syntax", extra("--sse-kms-key-id=$(id)"), `flag "--sse-kms-key-id" takes a plain name`},
		{"s3 endpoint flag not a url", extra("--endpoint-url file:///etc/passwd"), `flag "--endpoint-url" takes an http or https URL`},
		{"s3 region option", s3(map[string]string{"region": "-x"}), "options.region takes a plain name"},
		{"s3 endpoint option", s3(map[string]string{"endpoint": "s3.example"}), "options.endpoint takes an http or https URL"},
		{"s3 endpoint option with user", s3(map[string]string{"endpoint": "https://me@s3.example"}), "options.endpoint takes an http or https URL with no user name"},
		{"s3 opts", s3(map[string]string{"opts": "rw"}), "options.opts is read only by nfs mounts, not s3"},
		// nfs: options that run or create things, act on other mounts or
		// host files, lift nosuid/nodev, or change labels or identity.
		{"nfs helper", nfs("rw,helper=evil"), `entry "helper" is not allowed`},
		{"nfs x-mount.mkdir", nfs("x-mount.mkdir"), `entry "x-mount.mkdir" is not allowed`},
		{"nfs remount", nfs("remount,rw"), `entry "remount" is not allowed`},
		{"nfs bind", nfs("bind"), `entry "bind" is not allowed`},
		{"nfs loop", nfs("loop=/dev/loop0"), `entry "loop" is not allowed`},
		{"nfs suid", nfs("rw,suid"), `entry "suid" is not allowed`},
		{"nfs dev", nfs("dev"), `entry "dev" is not allowed`},
		{"nfs defaults", nfs("defaults"), `entry "defaults" is not allowed`},
		{"nfs selinux context", nfs("context=system_u:object_r:etc_t:s0"), `entry "context" is not allowed`},
		{"nfs user", nfs("user"), `entry "user" is not allowed`},
		{"nfs bg", nfs("bg"), `entry "bg" is not allowed`},
		{"nfs fsc", nfs("fsc"), `entry "fsc" is not allowed`},
		{"nfs clientaddr", nfs("clientaddr=10.0.0.9"), `entry "clientaddr" is not allowed`},
		{"nfs xprtsec", nfs("xprtsec=mtls"), `entry "xprtsec" is not allowed`},
		{"nfs case matters", nfs("RW"), `entry "RW" is not allowed`},
		// nfs: malformed entries and values.
		{"nfs flag with value", nfs("hard=1"), `entry "hard" takes no value`},
		{"nfs value missing", nfs("vers"), `entry "vers" needs a value`},
		{"nfs bad version", nfs("vers=5"), `entry "vers" takes one of`},
		{"nfs bad number", nfs("timeo=10s"), `entry "timeo" takes a whole number`},
		{"nfs bad sec", nfs("sec=sys:none"), `entry "sec" takes one of`},
		{"nfs space", nfs("rw, vers=4"), "must not contain spaces or quotes"},
		{"nfs quoted value", nfs(`rw,vers="4,helper=x"`), "must not contain spaces or quotes"},
		{"nfs single quote", nfs("rw,'suid'"), "must not contain spaces or quotes"},
		{"nfs newline", nfs("rw\nsuid"), "must not contain spaces or quotes"},
		{"nfs extra_args", MountSpec{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"extra_args": "--allow-delete"}}, "options.extra_args is read only by s3 mounts, not nfs"},
		// rclone and sshfs read neither extra_args nor opts.
		{"rclone cache mode", rclone(map[string]string{"vfs_cache_mode": "writes --rc"}), "options.vfs_cache_mode takes one of: off, minimal, writes, full"},
		{"rclone extra_args", rclone(map[string]string{"extra_args": "--rc --rc-addr=0.0.0.0:5572"}), "options.extra_args is read only by s3 mounts, not rclone"},
		{"rclone opts", rclone(map[string]string{"opts": "rw"}), "options.opts is read only by nfs mounts, not rclone"},
		{"sshfs extra_args", sshfs(map[string]string{"extra_args": "-o ProxyCommand=id"}), "options.extra_args is read only by s3 mounts, not sshfs"},
		{"sshfs opts", sshfs(map[string]string{"opts": "allow_root"}), "options.opts is read only by nfs mounts, not sshfs"},
	}
	for _, tc := range refused {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			// The shape is valid: only the allow list refuses it.
			if err := tc.m.Validate("/usr/local/bin/toolboxd"); err != nil {
				t.Fatalf("Validate = %v, want the shape accepted", err)
			}
			err := tc.m.ValidateToolOptions()
			if err == nil {
				t.Fatalf("ValidateToolOptions(%+v) accepted", tc.m.Options)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want it to contain %q", err, tc.want)
			}
		})
	}

	if err := (*MountSpec)(nil).ValidateToolOptions(); err == nil {
		t.Fatal("nil spec accepted")
	}
}

// A refusal names the flag and where it is, never a value: a value can be
// anything a caller pasted, and the error is returned and logged.
func TestMountSpecValidateToolOptionsDoesNotEchoValues(t *testing.T) {
	cases := []MountSpec{
		{Type: MountTypeS3, Source: "b", Target: "/d", Options: map[string]string{"extra_args": "--uid s3cr3tVALUE"}},
		{Type: MountTypeS3, Source: "b", Target: "/d", Options: map[string]string{"extra_args": "s3cr3tVALUE"}},
		{Type: MountTypeS3, Source: "b", Target: "/d", Options: map[string]string{"extra_args": "--sse=s3cr3tVALUE"}},
		{Type: MountTypeS3, Source: "b", Target: "/d", Options: map[string]string{"region": "s3cr3tVALUE!"}},
		{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"opts": "timeo=s3cr3tVALUE"}},
		{Type: MountTypeRclone, Source: "r:p", Target: "/d", Options: map[string]string{"vfs_cache_mode": "s3cr3tVALUE"}, Credentials: map[string]string{"rclone_conf": "[r]\ntype = s3\n"}},
		{Type: MountTypeRclone, Source: "r:p", Target: "/d", Credentials: map[string]string{"rclone_conf": "[r]\ntype = local\nkey_file = s3cr3tVALUE\n"}},
		{Type: MountTypeRclone, Source: "r:p", Target: "/d", Credentials: map[string]string{"rclone_conf": "[r]\ntype = sftp\nssh = s3cr3tVALUE\n"}},
		{Type: MountTypeRclone, Source: "r:p", Target: "/d", Credentials: map[string]string{"rclone_conf": "s3cr3tVALUE = 1\n"}},
	}
	for _, m := range cases {
		err := m.ValidateToolOptions()
		if err == nil {
			t.Fatalf("accepted %+v", m.Options)
		}
		if strings.Contains(err.Error(), "s3cr3tVALUE") {
			t.Fatalf("error %q echoes the value", err)
		}
	}
}

func TestMountArgCheck(t *testing.T) {
	cases := []struct {
		arg  mountArg
		v    string
		want string // "" = accepted
	}{
		{mountArg{kind: mountArgUint}, "0", ""},
		{mountArg{kind: mountArgUint}, "", "takes a whole number"},
		{mountArg{kind: mountArgUint}, "-1", "takes a whole number"},
		{mountArgTTL, "minimal", ""},
		{mountArg{kind: mountArgOctal}, "755", ""},
		{mountArg{kind: mountArgOctal}, "", "takes an octal file mode"},
		{mountArg{kind: mountArgOctal}, "0x1ff", "takes an octal file mode"},
		{mountArg{kind: mountArgEnum, words: []string{"a", "b"}}, "a", ""},
		{mountArg{kind: mountArgEnum, words: []string{"a", "b"}, sep: ":"}, "a:b", ""},
		{mountArg{kind: mountArgEnum, words: []string{"a", "b"}, sep: ":"}, "a:", "takes one of: a, b"},
		{mountArg{kind: mountArgEnum, words: []string{"a", "b"}}, "a:b", "takes one of: a, b"},
		{mountArg{kind: mountArgToken}, "alias/x_y.z-1", ""},
		{mountArg{kind: mountArgToken}, "", "takes a plain name"},
		{mountArg{kind: mountArgToken}, "a b", "takes a plain name"},
		{mountArg{kind: mountArgToken}, "a;b", "takes a plain name"},
		{mountArg{kind: mountArgURL}, "https://s3.example", ""},
		{mountArg{kind: mountArgURL}, "https://", "takes an http or https URL"},
		{mountArg{kind: mountArgURL}, "https://s3.example/ x", "takes an http or https URL"},
		{mountArg{kind: mountArgURL}, "%zz", "takes an http or https URL"},
		{mountArg{kind: mountArgWord}, "/var/cache/s3", ""},
		{mountArg{kind: mountArgWord}, "", "takes a value that does not start with -"},
		{mountArg{kind: mountArgWord}, "--log-directory=/etc", "takes a value that does not start with -"},
		{mountArg{}, "anything", "takes no value"},
	}
	for _, tc := range cases {
		got := tc.arg.check(tc.v)
		if tc.want == "" && got != "" {
			t.Errorf("check(%q) = %q, want accepted", tc.v, got)
		}
		if tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("check(%q) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// Every allow-listed NFS option and mount-s3 flag either takes no value or
// says what it takes, and none of the options this file refuses on purpose
// has crept into a table.
func TestMountOptionTablesLeaveOutHostPowers(t *testing.T) {
	for _, name := range []string{"--cache", "--log-directory", "-l", "--ca-bundle", "--profile", "--otlp-endpoint", "--bind", "--cache-xz", "--debug", "-d", "--debug-crt", "--log-metrics", "--no-log", "--auto-unmount", "--foreground", "-f", "--prefix", "--user-agent-prefix", "--max-cache-size"} {
		if _, ok := mountS3Flags[name]; ok {
			t.Errorf("mount-s3 flag %q is allow-listed", name)
		}
	}
	for _, name := range []string{"suid", "dev", "defaults", "helper", "x-mount.mkdir", "context", "fscontext", "defcontext", "rootcontext", "loop", "offset", "bind", "rbind", "move", "remount", "user", "users", "owner", "group", "bg", "fsc", "clientaddr", "mounthost", "xprtsec"} {
		if _, ok := mountNFSOptions[name]; ok {
			t.Errorf("nfs option %q is allow-listed", name)
		}
	}
	for name, arg := range mountS3Flags {
		if !strings.HasPrefix(name, "--") {
			t.Errorf("mount-s3 flag %q is not a long flag", name)
		}
		if arg.kind == mountArgEnum && len(arg.words) == 0 {
			t.Errorf("mount-s3 flag %q is an enum with no words", name)
		}
	}
	for name, arg := range mountNFSOptions {
		if arg.kind == mountArgEnum && len(arg.words) == 0 {
			t.Errorf("nfs option %q is an enum with no words", name)
		}
	}
}

// A mount already running when sandboxd restarts, with a spec the lists
// refuse, is kept only when every refused flag does no harm while its tool
// goes on running. The kept cases are the common ones an upgrade meets (an
// S3 cache folder, NFS defaults, bg, fsc); every other refusal, every
// rclone one included, still fails and the mount is torn down.
func TestMountSpecValidateRunningToolOptions(t *testing.T) {
	extra := func(args string) MountSpec {
		return MountSpec{Type: MountTypeS3, Source: "bucket", Target: "/d", Options: map[string]string{"extra_args": args}}
	}
	nfs := func(opts string) MountSpec {
		return MountSpec{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"opts": opts}}
	}
	rclone := func(source, conf string) MountSpec {
		return MountSpec{Type: MountTypeRclone, Source: source, Target: "/d", Credentials: map[string]string{"rclone_conf": conf}}
	}
	kept := []struct {
		name string
		m    MountSpec
	}{
		{"s3 cache folder", extra("--allow-delete --cache /var/cache/s3")},
		{"s3 cache = form with a size", extra("--cache=/mnt/nvme/cache --max-cache-size 10240 --uid 1000")},
		{"s3 log levels", extra("--debug -d --debug-crt --log-metrics --no-log")},
		{"s3 auto unmount", extra("--auto-unmount")},
		{"nfs defaults", nfs("defaults,vers=4.1")},
		{"nfs bg and fsc", nfs("rw,bg,fsc,hard")},
		{"nfs suid and dev", nfs("suid,dev")},
		{"nfs fstab words", nfs("auto,noauto,nouser,fg")},
		// Never read by the tool these types run, so nothing ran them.
		{"extra_args on nfs", MountSpec{Type: MountTypeNFS, Source: "h:/e", Target: "/d", Options: map[string]string{"extra_args": "--log-directory=/etc"}}},
		{"opts on s3", MountSpec{Type: MountTypeS3, Source: "b", Target: "/d", Options: map[string]string{"opts": "bind"}}},
		{"opts on rclone", MountSpec{Type: MountTypeRclone, Source: "r:p", Target: "/d", Options: map[string]string{"opts": "rw"}, Credentials: map[string]string{"rclone_conf": "[r]\ntype = s3\n"}}},
	}
	for _, tc := range kept {
		t.Run("keep/"+tc.name, func(t *testing.T) {
			if err := tc.m.ValidateRunningToolOptions(); err != nil {
				t.Fatalf("ValidateRunningToolOptions(%+v) = %v, want kept", tc.m.Options, err)
			}
		})
	}

	removed := []struct {
		name string
		m    MountSpec
		want string
	}{
		// The running tool writes where the spec says, uses the server's
		// own credentials or network, or sends data elsewhere.
		{"s3 log directory", extra("--cache /c --log-directory=/etc/cron.d"), `flag "--log-directory" is not allowed`},
		{"s3 log directory short", extra("-l /tmp/x"), `flag "-l" is not allowed`},
		{"s3 profile", extra("--profile default"), `flag "--profile" is not allowed`},
		{"s3 otlp endpoint", extra("--otlp-endpoint=http://collector:4318"), `flag "--otlp-endpoint" is not allowed`},
		{"s3 cache-xz", extra("--cache-xz other-bucket"), `flag "--cache-xz" is not allowed`},
		{"s3 ca bundle", extra("--ca-bundle /tmp/x.pem"), `flag "--ca-bundle" is not allowed`},
		{"s3 bind", extra("--bind eth1"), `flag "--bind" is not allowed`},
		{"s3 unknown", extra("--future-flag"), `flag "--future-flag" is not allowed`},
		{"s3 cache without a folder", extra("--cache"), `flag "--cache" needs a value`},
		{"s3 cache folder is a flag", extra("--cache --log-directory=/etc"), `flag "--cache" takes a value that does not start with -`},
		{"s3 cache size not a number", extra("--cache /c --max-cache-size big"), `flag "--max-cache-size" takes a whole number`},
		{"s3 region option", MountSpec{Type: MountTypeS3, Source: "b", Target: "/d", Options: map[string]string{"region": "-x"}}, "options.region takes a plain name"},
		// The kernel serves a server folder or file, or the mount acts
		// with labels or identities the server holds.
		{"nfs bind", nfs("bind"), `entry "bind" is not allowed`},
		{"nfs loop", nfs("loop=/dev/loop0"), `entry "loop" is not allowed`},
		{"nfs helper", nfs("defaults,helper=x"), `entry "helper" is not allowed`},
		{"nfs selinux context", nfs("context=system_u:object_r:etc_t:s0"), `entry "context" is not allowed`},
		{"nfs user", nfs("user"), `entry "user" is not allowed`},
		{"nfs xprtsec", nfs("xprtsec=mtls"), `entry "xprtsec" is not allowed`},
		{"nfs defaults takes no value", nfs("defaults=1"), `entry "defaults" takes no value`},
		{"nfs quotes", nfs(`rw,"bg"`), "must not contain spaces or quotes"},
		// rclone: nothing is kept.
		{"rclone local backend", rclone(":local:/etc", "#"), `backend "local"`},
		{"rclone ssh command", rclone("box:data", "[box]\ntype = sftp\nhost = h\nssh = sh -c id\n"), `option "ssh" is not allowed`},
		{"rclone key file", rclone("box:data", "[box]\ntype = sftp\nhost = h\nkey_file = /root/.ssh/id_ed25519\n"), `option "key_file" is not allowed`},
		{"rclone cache mode", MountSpec{Type: MountTypeRclone, Source: "r:p", Target: "/d", Options: map[string]string{"vfs_cache_mode": "all"}, Credentials: map[string]string{"rclone_conf": "[r]\ntype = s3\n"}}, "options.vfs_cache_mode takes one of"},
	}
	for _, tc := range removed {
		t.Run("remove/"+tc.name, func(t *testing.T) {
			if err := tc.m.ValidateToolOptions(); err == nil {
				t.Fatal("the allow lists accept it: not a running-mount case")
			}
			err := tc.m.ValidateRunningToolOptions()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateRunningToolOptions = %v, want %q", err, tc.want)
			}
		})
	}

	// Whatever the lists accept, a running mount keeps.
	for _, m := range []MountSpec{
		extra("--allow-delete --uid 1000 --metadata-ttl indefinite"),
		nfs("nfsvers=4.1,rsize=1048576,hard,timeo=600,_netdev"),
		rclone("r:p", "[r]\ntype = s3\n"),
		{Type: MountTypeSSHFS, Source: "u@h:/x", Target: "/d"},
	} {
		if err := m.ValidateToolOptions(); err != nil {
			t.Fatalf("ValidateToolOptions(%+v) = %v", m, err)
		}
		if err := m.ValidateRunningToolOptions(); err != nil {
			t.Fatalf("ValidateRunningToolOptions(%+v) = %v, want what the lists accept kept", m, err)
		}
	}
	if err := (*MountSpec)(nil).ValidateRunningToolOptions(); err == nil {
		t.Fatal("nil spec accepted")
	}
}

// The kept lists hold only flags the lists refuse (each is a running-mount
// exception, not a second allow list), and none that lets a running tool
// reach into the server.
func TestMountKeptListsLeaveOutHostPowers(t *testing.T) {
	for name := range mountS3KeptFlags {
		if _, ok := mountS3Flags[name]; ok {
			t.Errorf("mount-s3 flag %q is on both the allow list and the kept list", name)
		}
	}
	for _, name := range mountNFSKeptOptions {
		if _, ok := mountNFSOptions[name]; ok {
			t.Errorf("nfs option %q is on both the allow list and the kept list", name)
		}
	}
	for _, name := range []string{"--log-directory", "-l", "--profile", "--otlp-endpoint", "--bind", "--cache-xz", "--ca-bundle", "--foreground", "-f", "--prefix"} {
		if _, ok := mountS3RunningFlags[name]; ok {
			t.Errorf("mount-s3 flag %q may stay in a running mount", name)
		}
	}
	for _, name := range []string{"helper", "x-mount.mkdir", "context", "fscontext", "defcontext", "rootcontext", "loop", "offset", "bind", "rbind", "move", "remount", "user", "users", "owner", "group", "clientaddr", "mounthost", "xprtsec"} {
		if _, ok := mountNFSRunningOptions[name]; ok {
			t.Errorf("nfs option %q may stay in a running mount", name)
		}
	}
}
