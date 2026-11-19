package adapters

import (
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The allow list (models.MountSpec.ValidateToolOptions) and the S3 adapter
// must read extra_args the same way, or a word the list never saw could
// reach mount-s3. So for specs the list accepts, every word the adapter
// puts between --foreground and "--" is the adapter's own --profile or
// --prefix, or passes the same list again; the caller's words are exactly
// the tail of that run, in order; and only the bucket and the mount path
// come after "--".
func TestS3Build_ArgvIsWhatTheAllowListChecked(t *testing.T) {
	for _, extra := range []string{
		"",
		"--allow-delete --uid 1000",
		"  --uid=1000\t--gid 1000\n --dir-mode 0755 ",
		"--sse aws:kms --sse-kms-key-id arn:aws:kms:us-east-1:111122223333:key/abc --metadata-ttl indefinite",
		"--allow-other --max-threads 32 --part-size=8388608 --no-sign-request",
	} {
		for _, creds := range []map[string]string{nil, {"access_key_id": "A", "secret_access_key": "B"}} {
			spec := models.MountSpec{Type: models.MountTypeS3, Source: "s3://bucket/team/data", Target: "/d", ReadOnly: true,
				Options:     map[string]string{"region": "us-east-1", "endpoint": "https://s3.example", "extra_args": extra},
				Credentials: creds}
			if err := spec.ValidateToolOptions(); err != nil {
				t.Fatalf("the list refused %q: %v", extra, err)
			}
			plan, err := (S3{}).Build("sb", 0, spec, "/mnt/t", "/creds")
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if plan.Argv[0] != "mount-s3" || plan.Argv[1] != "--foreground" {
				t.Fatalf("argv = %v", plan.Argv)
			}
			dash := slices.Index(plan.Argv, "--")
			if dash < 0 || !slices.Equal(plan.Argv[dash+1:], []string{"bucket", "/mnt/t"}) {
				t.Fatalf("after --: %v", plan.Argv)
			}
			run := plan.Argv[2:dash]
			if words := strings.Fields(extra); len(words) > 0 && !slices.Equal(run[len(run)-len(words):], words) {
				t.Fatalf("extra_args %q became %v", extra, run)
			}
			var checked []string
			for i := 0; i < len(run); i++ {
				if run[i] == "--profile" || run[i] == "--prefix" {
					i++ // the adapter's own, with the value it chose
					continue
				}
				checked = append(checked, run[i])
			}
			again := models.MountSpec{Type: models.MountTypeS3, Options: map[string]string{"extra_args": strings.Join(checked, " ")}}
			if err := again.ValidateToolOptions(); err != nil {
				t.Fatalf("argv %v has words the list refuses: %v", plan.Argv, err)
			}
		}
	}
}
