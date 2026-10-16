package config

import (
	"strings"
	"testing"
)

var witnessEnvKeys = []string{
	"SB_AUDIT_WITNESS_BACKEND", "SB_AUDIT_WITNESS_S3_BUCKET", "SB_AUDIT_WITNESS_S3_PREFIX",
	"SB_AUDIT_WITNESS_S3_ENDPOINT", "SB_AUDIT_WITNESS_S3_REGION", "SB_AUDIT_WITNESS_S3_PATH_STYLE",
	"SB_NODE_ID", "SB_SECRET_AUDIT_RETENTION_DAYS", "SB_ENTERPRISE_MODE",
}

func TestAuditWitnessSettings(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		err   string
		check func(t *testing.T, c Config)
	}{
		{
			name: "unset means no witness",
			check: func(t *testing.T, c Config) {
				if c.AuditWitnessBackend != "" || c.AuditWitnessS3Prefix != "witness/" {
					t.Fatalf("defaults: backend=%q prefix=%q", c.AuditWitnessBackend, c.AuditWitnessS3Prefix)
				}
			},
		},
		{
			// Witness settings with no backend are inert: no SB_NODE_ID rule,
			// and the daemon never opens a witness from them.
			name: "settings without a backend are inert",
			env:  map[string]string{"SB_AUDIT_WITNESS_S3_BUCKET": "b"},
		},
		{
			name: "s3 projects every setting",
			env: map[string]string{
				"SB_AUDIT_WITNESS_BACKEND":       " S3 ",
				"SB_AUDIT_WITNESS_S3_BUCKET":     "witness-bkt",
				"SB_AUDIT_WITNESS_S3_PREFIX":     "evidence",
				"SB_AUDIT_WITNESS_S3_ENDPOINT":   "http://127.0.0.1:9000",
				"SB_AUDIT_WITNESS_S3_REGION":     "eu-west-1",
				"SB_AUDIT_WITNESS_S3_PATH_STYLE": "true",
				"SB_NODE_ID":                     "node-1",
				"SB_SECRET_AUDIT_RETENTION_DAYS": "45",
			},
			check: func(t *testing.T, c Config) {
				w := c.AuditWitnessConfig()
				if w.Backend != "s3" || w.NodeID != "node-1" || w.RetentionDays != 45 {
					t.Fatalf("witness config = %+v", w)
				}
				if w.S3.Bucket != "witness-bkt" || w.S3.Prefix != "evidence" || w.S3.Endpoint != "http://127.0.0.1:9000" || w.S3.Region != "eu-west-1" || !w.S3.PathStyle {
					t.Fatalf("witness s3 config = %+v", w.S3)
				}
			},
		},
		{
			name: "unknown backend",
			env:  map[string]string{"SB_AUDIT_WITNESS_BACKEND": "gcs", "SB_NODE_ID": "n1"},
			err:  `SB_AUDIT_WITNESS_BACKEND="gcs" is not supported`,
		},
		{
			name: "s3 without a bucket",
			env:  map[string]string{"SB_AUDIT_WITNESS_BACKEND": "s3", "SB_NODE_ID": "n1"},
			err:  "SB_AUDIT_WITNESS_S3_BUCKET is required",
		},
		{
			name: "s3 without SB_NODE_ID",
			env:  map[string]string{"SB_AUDIT_WITNESS_BACKEND": "s3", "SB_AUDIT_WITNESS_S3_BUCKET": "b"},
			err:  "SB_NODE_ID must be set",
		},
		{
			name: "endpoint is not a URL",
			env:  map[string]string{"SB_AUDIT_WITNESS_BACKEND": "s3", "SB_AUDIT_WITNESS_S3_BUCKET": "b", "SB_NODE_ID": "n1", "SB_AUDIT_WITNESS_S3_ENDPOINT": "minio:9000"},
			err:  "SB_AUDIT_WITNESS_S3_ENDPOINT must be an absolute http(s) URL",
		},
		{
			name: "enterprise needs an https endpoint",
			env: map[string]string{
				"SB_AUDIT_WITNESS_BACKEND": "s3", "SB_AUDIT_WITNESS_S3_BUCKET": "b", "SB_NODE_ID": "n1",
				"SB_AUDIT_WITNESS_S3_ENDPOINT": "http://minio:9000", "SB_ENTERPRISE_MODE": "true",
			},
			err: "SB_AUDIT_WITNESS_S3_ENDPOINT must use https when SB_ENTERPRISE_MODE=true",
		},
		{
			name: "s3 with the standalone id",
			env:  map[string]string{"SB_AUDIT_WITNESS_BACKEND": "s3", "SB_AUDIT_WITNESS_S3_BUCKET": "b", "SB_NODE_ID": "standalone"},
			err:  `not to "standalone"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Every key the cases use starts empty, so a developer's own
			// environment cannot change a case.
			for _, k := range witnessEnvKeys {
				t.Setenv(k, "")
			}
			t.Setenv("SB_PAT_TOKEN", "token")
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			cfg, err := Load()
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("Load() err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if c.check != nil {
				c.check(t, cfg)
			}
		})
	}
}
