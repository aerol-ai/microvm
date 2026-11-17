package volumes

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPlatformMountShape(t *testing.T) {
	tenant := TenantForOwnerRef("team:a")
	if TenantForOwnerRef(" ") != "" || tenant == "" || tenant[:2] != "t-" {
		t.Fatalf("tenant scopes %q", tenant)
	}
	for _, tc := range []struct {
		name   string
		m      models.MountSpec
		tenant string
		want   bool
	}{
		{"s3 volume", models.MountSpec{Type: models.MountTypeS3, Source: "b/p/" + tenant + "/data"}, tenant, true},
		{"s3 volume with no prefix", models.MountSpec{Type: models.MountTypeS3, Source: "b/" + tenant + "/data"}, tenant, true},
		{"s3 without a bucket", models.MountSpec{Type: models.MountTypeS3, Source: tenant + "/data"}, tenant, false},
		{"s3 url", models.MountSpec{Type: models.MountTypeS3, Source: "s3://b/" + tenant + "/data"}, tenant, false},
		{"nfs volume", models.MountSpec{Type: models.MountTypeNFS, Source: "h:/exp/" + tenant + "/data"}, tenant, true},
		{"nfs volume on a root export", models.MountSpec{Type: models.MountTypeNFS, Source: "h:/" + tenant + "/data"}, tenant, true},
		{"nfs without a host", models.MountSpec{Type: models.MountTypeNFS, Source: ":/" + tenant + "/data"}, tenant, false},
		{"nfs not clean", models.MountSpec{Type: models.MountTypeNFS, Source: "h:/a/../" + tenant + "/data"}, tenant, false},
		{"another tenant", models.MountSpec{Type: models.MountTypeS3, Source: "b/p/t-0000000000000000/data"}, tenant, false},
		{"a name that is not a volume name", models.MountSpec{Type: models.MountTypeS3, Source: "b/p/" + tenant + "/Data"}, tenant, false},
		{"operator scope", models.MountSpec{Type: models.MountTypeS3, Source: "b/p/op-main/data"}, "", true},
		{"operator sandbox, tenant segment", models.MountSpec{Type: models.MountTypeS3, Source: "b/p/" + tenant + "/data"}, "", false},
		{"sshfs", models.MountSpec{Type: "sshfs", Source: "h:/" + tenant + "/data"}, tenant, false},
	} {
		if got := PlatformMountShape(tc.m, tc.tenant); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPlatformMountFor(t *testing.T) {
	tenant := TenantForOwnerRef("team:a")
	b := Backend{Kind: BackendS3, S3Bucket: "vols", S3Prefix: "pfx", S3Region: "eu", NFSServer: "nfs.local", NFSExport: "/exports", NFSOptions: "vers=4"}
	s3 := models.MountSpec{Type: models.MountTypeS3, Source: "vols/pfx/" + tenant + "/data", Target: "/data", ReadOnly: true,
		Options: map[string]string{"endpoint": "http://elsewhere"}, Credentials: map[string]string{"access_key_id": "x"}}
	got, ok := PlatformMountFor(b, tenant, s3)
	if !ok || got.Source != s3.Source || got.Target != "/data" || !got.ReadOnly || got.Options["endpoint"] != "" || got.Options["region"] != "eu" || len(got.Credentials) != 0 {
		t.Fatalf("s3 rebuilt %+v ok=%v", got, ok)
	}
	nfs := models.MountSpec{Type: models.MountTypeNFS, Source: "nfs.local:/exports/" + tenant + "/data", Target: "/n"}
	if got, ok := PlatformMountFor(b, tenant, nfs); !ok || got.Options["opts"] != "vers=4" {
		t.Fatalf("nfs rebuilt %+v ok=%v", got, ok)
	}
	for name, m := range map[string]models.MountSpec{
		"another bucket":    {Type: models.MountTypeS3, Source: "other/pfx/" + tenant + "/data", Target: "/d"},
		"another prefix":    {Type: models.MountTypeS3, Source: "vols/x/" + tenant + "/data", Target: "/d"},
		"another tenant":    {Type: models.MountTypeS3, Source: "vols/pfx/t-0000000000000000/data", Target: "/d"},
		"another nfs host":  {Type: models.MountTypeNFS, Source: "nfs2.internal:/exports/" + tenant + "/data", Target: "/d"},
		"a bad volume name": {Type: models.MountTypeS3, Source: "vols/pfx/" + tenant + "/..", Target: "/d"},
		"no target":         {Type: models.MountTypeS3, Source: "vols/pfx/" + tenant + "/data"},
		"another type":      {Type: "rclone", Source: "vols/pfx/" + tenant + "/data", Target: "/d"},
		"an empty source":   {Type: models.MountTypeS3, Target: "/d"},
	} {
		if _, ok := PlatformMountFor(b, tenant, m); ok {
			t.Errorf("%s: taken", name)
		}
	}
	if _, ok := PlatformMountFor(b, "", s3); ok {
		t.Error("no tenant: taken")
	}
	if _, ok := PlatformMountFor(Backend{}, tenant, s3); ok {
		t.Error("no backend: taken")
	}
}

// A volume's record gives its location and tenant: a volume made before the
// operator changed the prefix mounts at the location it was made at, with
// this node's options, in this node's own bucket; nothing but a record of
// the sandbox's own tenant (or an operator scope, for an operator's
// sandbox) that names exactly this mount counts. A volume from before a
// bucket change falls back to the configuration check.
func TestPlatformMountFromRecord(t *testing.T) {
	tenant := TenantForOwnerRef("team:a")
	b := Backend{Kind: BackendS3, S3Bucket: "vols-new", S3Prefix: "p2", S3Region: "eu-west-1"}
	old := "vols-new/p1/" + tenant + "/data"
	vol := models.Volume{ID: "v1", Tenant: tenant, Name: "data", Backend: BackendS3, Source: old}
	att := models.VolumeAttachment{Tenant: tenant, VolumeID: "v1", SandboxID: "sb-1", Target: "/data", Source: old}
	m := models.MountSpec{Type: models.MountTypeS3, Source: old, Target: "/data", ReadOnly: true, Options: map[string]string{"endpoint": "http://elsewhere.example"}}
	got, ok := PlatformMountFromRecord(b, tenant, vol, att, m)
	if !ok || got.Source != old || got.Target != "/data" || !got.ReadOnly || got.Options["endpoint"] != "" || got.Options["region"] != "eu-west-1" {
		t.Fatalf("old location: %+v %v", got, ok)
	}
	otherBucket := vol
	otherBucket.Source = "vols-old/p1/" + tenant + "/data"
	otherAtt := att
	otherAtt.Source = otherBucket.Source
	otherMount := m
	otherMount.Source = otherBucket.Source
	if _, ok := PlatformMountFromRecord(b, tenant, otherBucket, otherAtt, otherMount); ok {
		t.Fatal("a record in another bucket: rebuilt from the record")
	}
	opVol := models.Volume{ID: "v2", Tenant: "op-main", Name: "shared", Backend: BackendS3, Source: "vols-new/p1/op-main/shared"}
	opAtt := models.VolumeAttachment{Tenant: "op-main", VolumeID: "v2", Target: "/shared", Source: opVol.Source}
	opMount := models.MountSpec{Type: models.MountTypeS3, Source: opVol.Source, Target: "/shared"}
	if _, ok := PlatformMountFromRecord(b, "", opVol, opAtt, opMount); !ok {
		t.Fatal("an operator's volume, from its own record")
	}
	// A record from before the source was kept: the location this node
	// builds for it.
	legacy := vol
	legacy.Source = ""
	here := "vols-new/p2/" + tenant + "/data"
	legacyAtt := att
	legacyAtt.Source = here
	if _, ok := PlatformMountFromRecord(b, tenant, legacy, legacyAtt, models.MountSpec{Type: models.MountTypeS3, Source: here, Target: "/data"}); !ok {
		t.Fatal("a record with no source")
	}
	with := func(f func(v *models.Volume, a *models.VolumeAttachment, m *models.MountSpec), tenant string) bool {
		v, a, mm := vol, att, m
		f(&v, &a, &mm)
		_, ok := PlatformMountFromRecord(b, tenant, v, a, mm)
		return ok
	}
	for name, f := range map[string]func(v *models.Volume, a *models.VolumeAttachment, m *models.MountSpec){
		"another volume's attachment":     func(_ *models.Volume, a *models.VolumeAttachment, _ *models.MountSpec) { a.VolumeID = "v9" },
		"an attachment at another target": func(_ *models.Volume, a *models.VolumeAttachment, _ *models.MountSpec) { a.Target = "/other" },
		"an attachment at another source": func(_ *models.Volume, a *models.VolumeAttachment, _ *models.MountSpec) {
			a.Source = "x/" + tenant + "/data"
		},
		"another tenant's volume": func(v *models.Volume, a *models.VolumeAttachment, _ *models.MountSpec) {
			v.Tenant, a.Tenant = "t-0000000000000000", "t-0000000000000000"
		},
		"a source not ending in its tenant": func(v *models.Volume, a *models.VolumeAttachment, m *models.MountSpec) {
			v.Source, a.Source, m.Source = "b/x/data", "b/x/data", "b/x/data"
		},
		"a source not ending in its name": func(v *models.Volume, a *models.VolumeAttachment, m *models.MountSpec) {
			src := "b/" + tenant + "/other"
			v.Source, a.Source, m.Source = src, src, src
		},
		"a mount the record does not name": func(_ *models.Volume, _ *models.VolumeAttachment, m *models.MountSpec) {
			m.Source = "vols-new/p2/" + tenant + "/data"
		},
		"another backend":         func(v *models.Volume, _ *models.VolumeAttachment, _ *models.MountSpec) { v.Backend = BackendNFS },
		"a mount of another type": func(_ *models.Volume, _ *models.VolumeAttachment, m *models.MountSpec) { m.Type = models.MountTypeNFS },
		"a source that is not clean": func(v *models.Volume, a *models.VolumeAttachment, m *models.MountSpec) {
			src := "b/../" + tenant + "/data"
			v.Source, a.Source, m.Source = src, src, src
		},
	} {
		if with(f, tenant) {
			t.Errorf("%s: taken", name)
		}
	}
	if with(func(*models.Volume, *models.VolumeAttachment, *models.MountSpec) {}, "") {
		t.Error("a team's volume taken for an operator's sandbox")
	}
	if _, ok := PlatformMountFromRecord(Backend{Kind: BackendS3}, tenant, legacy, legacyAtt, models.MountSpec{Type: models.MountTypeS3, Source: here, Target: "/data"}); ok {
		t.Error("a record with no source, on a node with no bucket")
	}
}

// A rebuild from a volume's record keeps a volume made before a prefix or
// export change, but only on this node's own platform store: the record's
// bucket must be the node's bucket and its NFS server the node's server.
func TestRebuildFromRecordStaysOnThePlatformStore(t *testing.T) {
	s3 := Backend{Kind: BackendS3, S3Bucket: "platform-volumes", S3Prefix: "vols",
		S3AccessKeyID: "AKIANODE", S3SecretAccessKey: "node-secret"}
	nfs := Backend{Kind: BackendNFS, NFSServer: "nfs.platform", NFSExport: "/exports", NFSOptions: "vers=4.1"}

	for _, tc := range []struct {
		name string
		b    Backend
		vol  models.Volume
		want bool
	}{
		{"s3: another bucket", s3, models.Volume{ID: "v1", Tenant: "op-x", Name: "data", Backend: BackendS3,
			Source: "other-bucket/any/op-x/data"}, false},
		{"nfs: another server", nfs, models.Volume{ID: "v2", Tenant: "op-x", Name: "data", Backend: BackendNFS,
			Source: "10.0.9.9:/srv/other/op-x/data"}, false},
		// Same store, older prefix or export: still rebuilt from the record.
		{"s3: same bucket, older prefix", s3, models.Volume{ID: "v3", Tenant: "op-x", Name: "data", Backend: BackendS3,
			Source: "platform-volumes/old-prefix/op-x/data"}, true},
		{"nfs: same server, older export", nfs, models.Volume{ID: "v4", Tenant: "op-x", Name: "data", Backend: BackendNFS,
			Source: "nfs.platform:/old-exports/op-x/data"}, true},
	} {
		m := models.MountSpec{Type: models.MountType(tc.vol.Backend), Source: tc.vol.Source, Target: "/data"}
		att := models.VolumeAttachment{Tenant: tc.vol.Tenant, VolumeID: tc.vol.ID, SandboxID: "sb-w", Source: m.Source, Target: m.Target}
		out, ok := PlatformMountFromRecord(tc.b, "", tc.vol, att, m)
		if ok != tc.want {
			t.Errorf("%s: ok = %v (mount %q), want %v", tc.name, ok, out.Source, tc.want)
		}
	}
}
