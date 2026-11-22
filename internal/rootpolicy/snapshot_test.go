package rootpolicy

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func overlayActive(own string, lower ...string) []Mount {
	var dirs []string
	for _, l := range lower {
		dirs = append(dirs, layers+"/"+l+"/fs")
	}
	return []Mount{{Type: "overlay", Source: "overlay", Options: []string{"index=off",
		"workdir=" + layers + "/" + own + "/work", "upperdir=" + layers + "/" + own + "/fs", "lowerdir=" + strings.Join(dirs, ":")}}}
}

// TestImageLayers (M1 PR 7): only the image's own layer folders of an
// active snapshot, top first; nothing of the container's writable layer,
// and nothing outside the snapshotter's root.
func TestImageLayers(t *testing.T) {
	p := testPolicy()
	for _, tc := range []struct {
		name string
		ms   []Mount
		want []string
		rule Rule
	}{
		{"an image of two layers", overlayActive("9", "2", "1"), []string{layers + "/2/fs", layers + "/1/fs"}, ""},
		{"a snapshot with no parent", []Mount{{Type: "bind", Source: layers + "/4/fs", Options: []string{"rw", "rbind"}}}, nil, ""},
		{"no mount", nil, nil, RuleSnapshotMount},
		{"two mounts", append(overlayActive("9", "1"), overlayActive("8", "1")...), nil, RuleSnapshotMount},
		{"a view", []Mount{{Type: "bind", Source: layers + "/4/fs", Options: []string{"ro", "rbind"}}}, nil, RuleSnapshot},
		{"an overlay with no upper", []Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=" + layers + "/2/fs:" + layers + "/1/fs"}}}, nil, RuleSnapshot},
		{"a lower outside the root", []Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=" + layers + "/9/fs", "workdir=" + layers + "/9/work", "lowerdir=/etc"}}}, nil, RuleSnapshotMount},
		{"a lower climbing out", []Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=" + layers + "/9/fs", "workdir=" + layers + "/9/work", "lowerdir=" + layers + "/../../../etc/fs"}}}, nil, RuleSnapshotMount},
		{"a lower's subfolder", []Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=" + layers + "/9/fs", "workdir=" + layers + "/9/work", "lowerdir=" + layers + "/1/fs/etc"}}}, nil, RuleSnapshotMount},
		{"no lower", []Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=" + layers + "/9/fs", "workdir=" + layers + "/9/work"}}}, nil, RuleSnapshotMount},
		{"another type", []Mount{{Type: "ext4", Source: "/dev/sda"}}, nil, RuleSnapshotMount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ImageLayers(p, tc.ms)
			if RuleOf(err) != tc.rule || (tc.rule == "") != (err == nil) {
				t.Fatalf("err %v (rule %q), want rule %q", err, RuleOf(err), tc.rule)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("layers %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWritableLayer: an active snapshot's own folder and number, from its
// upper folder or its bind, and only one under the snapshotter's root.
func TestWritableLayer(t *testing.T) {
	p := testPolicy()
	for _, tc := range []struct {
		name string
		ms   []Mount
		dir  string
		n    uint64
		rule Rule
	}{
		{"an overlay", overlayActive("9", "2", "1"), layers + "/9", 9, ""},
		{"a bind", []Mount{{Type: "bind", Source: layers + "/12/fs", Options: []string{"rw", "rbind"}}}, layers + "/12", 12, ""},
		{"an upper outside the root", []Mount{{Type: "overlay", Source: "overlay", Options: []string{"upperdir=/var/lib/sandboxd/fs", "workdir=/var/lib/sandboxd/work", "lowerdir=" + layers + "/1/fs"}}}, "", 0, RuleSnapshotMount},
		{"a view", []Mount{{Type: "bind", Source: layers + "/12/fs", Options: []string{"ro", "rbind"}}}, "", 0, RuleSnapshot},
		{"a number past 64 bits", []Mount{{Type: "bind", Source: layers + "/99999999999999999999/fs", Options: []string{"rw", "rbind"}}}, "", 0, RuleSnapshotMount},
		{"no mount", nil, "", 0, RuleSnapshotMount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, n, err := WritableLayer(p, tc.ms)
			if RuleOf(err) != tc.rule || (tc.rule == "") != (err == nil) {
				t.Fatalf("err %v, want rule %q", err, tc.rule)
			}
			if dir != tc.dir || n != tc.n {
				t.Fatalf("%q %d, want %q %d", dir, n, tc.dir, tc.n)
			}
		})
	}
}

// TestQuotaProjectAndBytes: projects come only from AerolVM's own range,
// and a quota's size is bounded; zero would lift a limit.
func TestQuotaProjectAndBytes(t *testing.T) {
	for _, tc := range []struct {
		n    uint64
		want uint32
		ok   bool
	}{
		{1, QuotaProjectBase + 1, true}, {QuotaProjectSpan, 1<<31 - 1, true},
		{0, 0, false}, {QuotaProjectSpan + 1, 0, false}, {1 << 40, 0, false},
	} {
		got, err := QuotaProject(tc.n)
		if (err == nil) != tc.ok || got != tc.want || (err != nil && RuleOf(err) != RuleDiskQuota) {
			t.Errorf("QuotaProject(%d) = %d, %v", tc.n, got, err)
		}
	}
	for b, ok := range map[uint64]bool{0: false, 1: false, MinQuotaBytes - 1: false, MinQuotaBytes: true, 5 << 30: true, MaxQuotaBytes: true, MaxQuotaBytes + 1: false} {
		if err := CheckQuotaBytes(b); (err == nil) != ok || (err != nil && RuleOf(err) != RuleDiskQuota) {
			t.Errorf("CheckQuotaBytes(%d) = %v", b, err)
		}
	}
}

// TestCheckImageUser: every USER form containerd reads passes; a control
// character, invalid UTF-8 or a string past the bound does not.
func TestCheckImageUser(t *testing.T) {
	for u, ok := range map[string]bool{
		"": true, "app": true, "1000": true, "app:wheel": true, "1000:1000": true, "user.name-1": true, "дмитрий": true,
		"app\nroot": false, "app\x00": false, "\xff": false, strings.Repeat("a", MaxImageUserLen): true, strings.Repeat("a", MaxImageUserLen+1): false,
	} {
		if err := CheckImageUser(u); (err == nil) != ok || (err != nil && RuleOf(err) != RuleImageUser) {
			t.Errorf("CheckImageUser(%q) = %v", u, err)
		}
	}
}

func FuzzImageLayers(f *testing.F) {
	f.Add("overlay", "overlay", "index=off|workdir="+layers+"/9/work|upperdir="+layers+"/9/fs|lowerdir="+layers+"/2/fs:"+layers+"/1/fs")
	f.Add("overlay", "overlay", "upperdir="+layers+"/9/fs|workdir="+layers+"/9/work|lowerdir=/etc:/")
	f.Add("bind", layers+"/1/fs", "rw|rbind")
	f.Add("bind", layers+"/1/fs", "ro|rbind")
	f.Add("overlay", "overlay", "lowerdir="+layers+"/1/fs")
	p := testPolicy()
	f.Fuzz(func(t *testing.T, typ, src, opts string) {
		got, err := ImageLayers(p, []Mount{{Type: typ, Source: src, Options: strings.Split(opts, "|")}})
		if err != nil {
			return
		}
		for _, l := range got {
			if !layerFolder.MatchString(l) || !strings.HasSuffix(l, "/fs") {
				t.Fatalf("layer %q passed", l)
			}
		}
	})
}

func FuzzWritableLayer(f *testing.F) {
	f.Add("overlay", "overlay", "index=off|workdir="+layers+"/9/work|upperdir="+layers+"/9/fs|lowerdir="+layers+"/2/fs")
	f.Add("overlay", "overlay", "upperdir=/etc/fs|workdir=/etc/work|lowerdir="+layers+"/2/fs")
	f.Add("bind", layers+"/1/fs", "rw|rbind")
	f.Add("bind", layers+"/18446744073709551616/fs", "rw|rbind")
	p := testPolicy()
	dirOf := regexp.MustCompile(`^` + regexp.QuoteMeta(layers) + `/([0-9]{1,20})$`)
	f.Fuzz(func(t *testing.T, typ, src, opts string) {
		dir, n, err := WritableLayer(p, []Mount{{Type: typ, Source: src, Options: strings.Split(opts, "|")}})
		if err != nil {
			return
		}
		m := dirOf.FindStringSubmatch(dir)
		if m == nil {
			t.Fatalf("folder %q passed", dir)
		}
		if got, perr := strconv.ParseUint(m[1], 10, 64); perr != nil || got != n {
			t.Fatalf("folder %q, number %d", dir, n)
		}
	})
}

func FuzzQuotaProject(f *testing.F) {
	for _, n := range []uint64{0, 1, QuotaProjectSpan, QuotaProjectSpan + 1, 1 << 63} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, n uint64) {
		got, err := QuotaProject(n)
		if err != nil {
			return
		}
		if got < QuotaProjectBase || got >= 1<<31 || uint64(got-QuotaProjectBase) != n {
			t.Fatalf("snapshot %d got project %d", n, got)
		}
	})
}

func FuzzCheckImageUser(f *testing.F) {
	for _, u := range []string{"", "app", "1000:1000", "a\nb", "\xff"} {
		f.Add(u)
	}
	f.Fuzz(func(t *testing.T, u string) {
		if CheckImageUser(u) != nil {
			return
		}
		if len(u) > MaxImageUserLen || !utf8.ValidString(u) || strings.IndexFunc(u, unicode.IsControl) >= 0 {
			t.Fatalf("%q passed", u)
		}
	})
}
