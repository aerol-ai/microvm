package config

import "testing"

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
