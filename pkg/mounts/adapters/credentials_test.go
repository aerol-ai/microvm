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

// TestS3StaticCredentials: an access key id or a secret means the mount's
// own profile; a session token alone, or blanks, is no key.
func TestS3StaticCredentials(t *testing.T) {
	for _, tc := range []struct {
		creds map[string]string
		want  bool
	}{
		{map[string]string{"access_key_id": "a"}, true},
		{map[string]string{"secret_access_key": "s"}, true},
		{map[string]string{"session_token": "t"}, false},
		{map[string]string{"access_key_id": " "}, false},
		{nil, false},
	} {
		if got := S3StaticCredentials(tc.creds); got != tc.want {
			t.Errorf("%v: %v", tc.creds, got)
		}
	}
}
