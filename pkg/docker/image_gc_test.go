package docker

import "testing"

func TestIsImageRemoveBenignError(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    bool
	}{
		{
			name:    "404 not found",
			message: `docker API DELETE /images/foo failed with status 404: No such image: foo`,
			want:    true,
		},
		{
			name:    "409 still in use",
			message: `docker API DELETE /images/foo failed with status 409: image is being used by running container abc`,
			want:    true,
		},
		{
			name:    "500 internal",
			message: `docker API DELETE /images/foo failed with status 500: server error`,
			want:    false,
		},
		{
			name:    "transport error",
			message: `connection refused`,
			want:    false,
		},
		{
			name:    "empty",
			message: "",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isImageRemoveBenignError(tc.message); got != tc.want {
				t.Fatalf("isImageRemoveBenignError(%q) = %v, want %v", tc.message, got, tc.want)
			}
		})
	}
}
