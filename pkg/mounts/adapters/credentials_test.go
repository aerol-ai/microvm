package adapters

import (
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCredentialKeys: the keys each adapter reads, and a copy each call,
// so a caller cannot change the list.
func TestCredentialKeys(t *testing.T) {
	for typ, want := range map[models.MountType][]string{
		models.MountTypeS3:     {"access_key_id", "secret_access_key", "session_token"},
		models.MountTypeSSHFS:  {"private_key_pem"},
		models.MountTypeRclone: {"rclone_conf"},
		models.MountTypeNFS:    nil,
	} {
		got := CredentialKeys(typ)
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", typ, got, want)
		}
		if len(got) > 0 {
			got[0] = "changed"
			if CredentialKeys(typ)[0] == "changed" {
				t.Fatalf("%s: the list is shared", typ)
			}
		}
	}
}
