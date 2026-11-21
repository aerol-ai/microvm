package config

import (
	"strings"
	"testing"
)

// A platform volume's mount is built from these settings, not from the
// caller, so they are held to the mount-tool allow lists once, at boot: a
// bad value stops the daemon naming the setting instead of failing every
// create with a 400 the caller cannot fix. Both backends' values are
// checked when set, since a volume keeps the backend it was made on.
func TestPlatformVolumesConfigValidateMountOptions(t *testing.T) {
	nfs := func(opts string) PlatformVolumesConfig {
		return PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendNFS, NFSServer: "h", NFSExport: "/e", NFSOptions: opts}
	}
	s3 := func(region, endpoint string) PlatformVolumesConfig {
		return PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendS3, S3Bucket: "b", S3Region: region, S3Endpoint: endpoint}
	}
	for _, tc := range []struct {
		name string
		cfg  PlatformVolumesConfig
		want string // "" = accepted
	}{
		{"nfs version", nfs("vers=4.1"), ""},
		{"nfs efs line", nfs("nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport,_netdev"), ""},
		{"nfs defaults", nfs("defaults,vers=4.1"), `SB_PLATFORM_VOLUMES_NFS_OPTIONS: options.opts entry "defaults" is not allowed`},
		{"nfs fsc", nfs("vers=4.1,fsc"), `SB_PLATFORM_VOLUMES_NFS_OPTIONS: options.opts entry "fsc"`},
		{"nfs spaces", nfs("vers=4.1, hard"), "SB_PLATFORM_VOLUMES_NFS_OPTIONS: options.opts must not contain spaces"},
		{"s3 region and endpoint", s3("eu-west-1", "https://s3.example:9000"), ""},
		{"s3 bad region", s3("eu west", ""), "SB_PLATFORM_VOLUMES_S3_REGION: options.region takes a plain name"},
		{"s3 endpoint without scheme", s3("", "minio:9000"), "SB_PLATFORM_VOLUMES_S3_ENDPOINT: options.endpoint takes an http or https URL"},
		{"s3 backend, bad nfs options left set", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendS3, S3Bucket: "b", NFSOptions: "helper=x"}, "SB_PLATFORM_VOLUMES_NFS_OPTIONS"},
		{"disabled, nothing checked", PlatformVolumesConfig{NFSOptions: "helper=x", S3Endpoint: "nope"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Validate() = %v, want accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

// UC-17: a disabled platform-volumes config is always valid; an enabled one
// fails fast at boot unless the selected backend's required fields are present.
func TestPlatformVolumesConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     PlatformVolumesConfig
		wantErr bool
	}{
		{"disabled-ignores-fields", PlatformVolumesConfig{Enabled: false, Backend: "nonsense"}, false},
		{"s3-ok", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendS3, S3Bucket: "b"}, false},
		{"s3-missing-bucket", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendS3}, true},
		{"nfs-ok", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendNFS, NFSServer: "h", NFSExport: "/e"}, false},
		{"nfs-missing-server", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendNFS, NFSExport: "/e"}, true},
		{"nfs-missing-export", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendNFS, NFSServer: "h"}, true},
		{"unknown-backend", PlatformVolumesConfig{Enabled: true, Backend: "ftp", S3Bucket: "b"}, true},
		{"negative-quota", PlatformVolumesConfig{Enabled: true, Backend: PlatformVolumesBackendS3, S3Bucket: "b", MaxPerTenant: -1}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
