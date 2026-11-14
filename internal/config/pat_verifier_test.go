package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/volumes"
)

// TestPATVerifierConfig: SB_PAT_TOKEN_SHA256 loads, a node whose own token
// is not listed is node-local and sends no PAT to peers, and its operator
// volume scope is the PAT holders' one.
func TestPATVerifierConfig(t *testing.T) {
	operatorPAT := "operator-pat-token"
	opHash := PATSHA256(operatorPAT)
	prevHash := PATSHA256("previous-pat-token")
	legacyScope, err := volumes.OperatorScope("", operatorPAT)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		hashes      []string
		local       bool
		peerPAT     string
		volumeScope string
		accepted    []string
	}
	cases := []struct {
		name    string
		pat     string
		env     map[string]string
		want    want
		wantErr string
	}{
		{name: "unset: the node holds the PAT, as before", pat: operatorPAT,
			want: want{peerPAT: operatorPAT, accepted: []string{opHash}}},
		{name: "a joined worker: its own token, the PAT's hash", pat: "local-random-token",
			env:  map[string]string{"SB_PAT_TOKEN_SHA256": opHash},
			want: want{hashes: []string{opHash}, local: true, volumeScope: legacyScope, accepted: []string{opHash}}},
		{name: "upper case, spaces and a duplicate are cleaned", pat: "local-random-token",
			env:  map[string]string{"SB_PAT_TOKEN_SHA256": " " + strings.ToUpper(opHash) + " , " + prevHash + "," + opHash + ","},
			want: want{hashes: []string{opHash, prevHash}, local: true, volumeScope: legacyScope, accepted: []string{opHash, prevHash}}},
		{name: "the node's token is the listed PAT: not local", pat: operatorPAT,
			env:  map[string]string{"SB_PAT_TOKEN_SHA256": opHash},
			want: want{hashes: []string{opHash}, peerPAT: operatorPAT, accepted: []string{opHash}}},
		{name: "a pinned scope wins over the derived one", pat: "local-random-token",
			env:  map[string]string{"SB_PAT_TOKEN_SHA256": opHash, "SB_OPERATOR_VOLUME_SCOPE": "op-pinned"},
			want: want{hashes: []string{opHash}, local: true, volumeScope: "op-pinned", accepted: []string{opHash}}},
		{name: "a previous PAT on a node that holds the PAT is listed too", pat: operatorPAT,
			env:  map[string]string{"SB_PAT_TOKEN_PREVIOUS": "previous-pat-token", "SB_OPERATOR_VOLUME_SCOPE": "op-pinned"},
			want: want{peerPAT: operatorPAT, volumeScope: "op-pinned", accepted: []string{opHash, prevHash}}},
		{name: "not hex", pat: "x", env: map[string]string{"SB_PAT_TOKEN_SHA256": strings.Repeat("z", 64)},
			wantErr: "SB_PAT_TOKEN_SHA256"},
		{name: "too short", pat: "x", env: map[string]string{"SB_PAT_TOKEN_SHA256": "abc123"},
			wantErr: "is not a SHA-256"},
	}
	keys := []string{"SB_PAT_TOKEN_SHA256", "SB_OPERATOR_VOLUME_SCOPE", "SB_PAT_TOKEN_PREVIOUS"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range keys {
				t.Setenv(k, tc.env[k])
			}
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", tc.pat)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.PATTokenSHA256, tc.want.hashes) {
				t.Fatalf("PATTokenSHA256 = %v, want %v", cfg.PATTokenSHA256, tc.want.hashes)
			}
			if cfg.PATIsNodeLocal() != tc.want.local || cfg.ClusterPeerPAT() != tc.want.peerPAT {
				t.Fatalf("local = %v peer PAT = %q, want %v %q", cfg.PATIsNodeLocal(), cfg.ClusterPeerPAT(), tc.want.local, tc.want.peerPAT)
			}
			if cfg.OperatorVolumeScope != tc.want.volumeScope {
				t.Fatalf("OperatorVolumeScope = %q, want %q", cfg.OperatorVolumeScope, tc.want.volumeScope)
			}
			if got := cfg.OperatorPATSHA256(); !slices.Equal(got, tc.want.accepted) {
				t.Fatalf("OperatorPATSHA256 = %v, want %v", got, tc.want.accepted)
			}
		})
	}
}

// The hash check: only a listed token matches, and an empty one never does.
func TestPATMatchesSHA256(t *testing.T) {
	hashes := []string{PATSHA256("a"), PATSHA256("b")}
	for _, tc := range []struct {
		token string
		want  bool
	}{{"a", true}, {"b", true}, {"c", false}, {"", false}} {
		if got := PATMatchesSHA256(tc.token, hashes); got != tc.want {
			t.Fatalf("PATMatchesSHA256(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
	if PATMatchesSHA256("a", nil) {
		t.Fatal("no hashes matched a token")
	}
	// The form `printf %s "$PAT" | sha256sum` prints.
	if got := PATSHA256("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("PATSHA256(abc) = %s", got)
	}
}
