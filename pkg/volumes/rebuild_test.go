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
		"another nfs host":  {Type: models.MountTypeNFS, Source: "evil:/exports/" + tenant + "/data", Target: "/d"},
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
