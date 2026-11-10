package safety

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mirror-sync.sh --tf-providers fills tf-providers/, the Terraform network
// mirror tf_init_failover falls back to. These tests run it with terraform,
// curl and aws replaced, so nothing reaches a registry or AWS.

// fakeTerraformMirror stands in for terraform. `providers mirror` writes one
// provider version (FAKE_TF_VERSION, default 3.9.1) for each -platform into
// the output directory, as the real command lays it out; `init` passes only
// when TF_CLI_CONFIG_FILE names a network mirror at FAKE_TF_WANT_URL. Each
// call logs its arguments and its CLI config's text.
const fakeTerraformMirror = `#!/usr/bin/env bash
cfg=""
[ -n "${TF_CLI_CONFIG_FILE:-}" ] && cfg="$(tr '\n' ' ' <"$TF_CLI_CONFIG_FILE")"
echo "terraform $* tfrc=[${cfg}] cache=[${TF_PLUGIN_CACHE_DIR:-}] chdir_tf=$(ls "${1#-chdir=}" 2>/dev/null | tr '\n' ' ')" >>"$TOOL_LOG"
shift # -chdir=
case "$1 $2" in
  "providers mirror")
    [ -z "${FAKE_TF_MIRROR_FAIL:-}" ] || exit 1
    v="${FAKE_TF_VERSION:-3.9.1}"; out="${@: -1}"; d="$out/registry.terraform.io/hashicorp/random"
    mkdir -p "$d"
    printf '{"versions":{"%s":{}}}\n' "$v" >"$d/index.json"
    arch="{"
    for a in "$@"; do
      case "$a" in -platform=*) p="${a#-platform=}"
        echo "zip-$v-$p" >"$d/terraform-provider-random_${v}_${p}.zip"
        arch="$arch\"$p\":{\"url\":\"terraform-provider-random_${v}_${p}.zip\"},";;
      esac
    done
    printf '{"archives":%s}}\n' "${arch%,}" >"$d/$v.json"
    ;;
  "init -backend=false")
    case "$cfg" in *"url = \"${FAKE_TF_WANT_URL}\""*) echo "- Installed hashicorp/random v3.9.1 (verified checksum)";; *) echo "Error: Failed to install provider" >&2; exit 1;; esac
    ;;
  *) echo "fake terraform: $*" >&2; exit 2 ;;
esac
`

// fakeCurlStatus serves $FAKE_WEB/<host>/<path> with -w '%{http_code}':
// 200 and the body, or 404; FAKE_CURL_CODE forces another answer.
const fakeCurlStatus = `#!/usr/bin/env bash
echo "curl $*" >>"$TOOL_LOG"
out="" url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
f="$FAKE_WEB/${url#https://}"
if [[ -n "${FAKE_CURL_CODE:-}" ]]; then printf '%s' "$FAKE_CURL_CODE"; exit 0; fi
if [[ -f "$f" ]]; then cp "$f" "$out"; printf 200; else printf 404; fi
`

const tfMirrorPublic = "https://aerolvm-downloads.s3.us-east-1.amazonaws.com/tf-providers/"

func newTFSyncRig(t *testing.T, env ...string) (*syncRig, string) {
	t.Helper()
	r := newSyncRig(t)
	for name, body := range map[string]string{"terraform": fakeTerraformMirror, "curl": fakeCurlStatus} {
		mustWrite(t, filepath.Join(r.binDir, name), body)
		if err := os.Chmod(filepath.Join(r.binDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tfDir := t.TempDir()
	mustWrite(t, filepath.Join(tfDir, "versions.tf"), "terraform {}\n")
	mustWrite(t, filepath.Join(tfDir, "main.tf"), "# resources\n")
	mustWrite(t, filepath.Join(tfDir, "bootstrap.sh.tftpl"), "not a .tf file\n")
	r.env = append(env, "FAKE_TF_WANT_URL="+tfMirrorPublic)
	return r, tfDir
}

func indexVersions(t *testing.T, raw string) []string {
	t.Helper()
	var idx struct {
		Versions map[string]struct{} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(raw), &idx); err != nil {
		t.Fatalf("index.json %q: %v", raw, err)
	}
	out := make([]string, 0, len(idx.Versions))
	for v := range idx.Versions {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

const tfIndexKey = "aerolvm-downloads/tf-providers/registry.terraform.io/hashicorp/random/index.json"

func TestMirrorSyncTFProvidersUploadsAMirrorAndKeepsOldVersionsListed(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	t.Run("first sync: every platform, index.json last", func(t *testing.T) {
		r, tfDir := newTFSyncRig(t)
		r.run("--tf-providers", "--terraform-dir", tfDir)
		if r.code != 0 {
			t.Fatalf("exit %d", r.code)
		}
		got := r.uploaded()
		for _, p := range []string{"linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"} {
			key := "aerolvm-downloads/tf-providers/registry.terraform.io/hashicorp/random/terraform-provider-random_3.9.1_" + p + ".zip"
			if got[key] != "zip-3.9.1-"+p+"\n" {
				t.Errorf("%s = %q, want the package for %s", key, got[key], p)
			}
		}
		if _, ok := got["aerolvm-downloads/tf-providers/registry.terraform.io/hashicorp/random/3.9.1.json"]; !ok {
			t.Error("the version file 3.9.1.json was not uploaded")
		}
		if v := indexVersions(t, got[tfIndexKey]); strings.Join(v, ",") != "3.9.1" {
			t.Errorf("index.json lists %v, want [3.9.1]", v)
		}
		syncAt, indexAt := strings.Index(r.logs, "aws s3 sync"), strings.Index(r.logs, "aws s3 cp")
		if syncAt < 0 || indexAt < syncAt || !strings.Contains(r.logs, `--exclude *index.json`) {
			t.Errorf("index.json must go up after the packages, and not with them:\n%s", r.logs)
		}
		mirrorCall := firstLine(r.logs, "terraform -chdir=")
		if !strings.Contains(mirrorCall, "tfrc=[]") || !strings.Contains(mirrorCall, "cache=[]") {
			t.Errorf("providers mirror ran with the operator's CLI config or plugin cache: %s", mirrorCall)
		}
		if !strings.Contains(mirrorCall, "main.tf versions.tf") || strings.Contains(mirrorCall, "tftpl") {
			t.Errorf("providers mirror did not run on a copy of just the .tf files: %s", mirrorCall)
		}
	})

	t.Run("a newer version: the mirror's older ones stay listed", func(t *testing.T) {
		r, tfDir := newTFSyncRig(t, "FAKE_TF_VERSION=3.10.0")
		r.onPublicMirror("tf-providers/registry.terraform.io/hashicorp/random/index.json", `{"versions":{"3.9.1":{}}}`)
		r.run("--tf-providers", "--terraform-dir", tfDir)
		if r.code != 0 {
			t.Fatalf("exit %d", r.code)
		}
		if v := indexVersions(t, r.uploaded()[tfIndexKey]); strings.Join(v, ",") != "3.10.0,3.9.1" {
			t.Errorf("index.json lists %v, want both 3.10.0 and 3.9.1", v)
		}
	})

	for name, env := range map[string]string{
		"the mirror's index.json cannot be read": "FAKE_CURL_CODE=503",
		"terraform providers mirror fails":       "FAKE_TF_MIRROR_FAIL=1",
	} {
		t.Run(name+": nothing uploaded", func(t *testing.T) {
			r, tfDir := newTFSyncRig(t, env)
			r.run("--tf-providers", "--terraform-dir", tfDir)
			if r.code == 0 {
				t.Fatal("exit 0, want a failure")
			}
			if got := r.uploaded(); len(got) != 0 {
				t.Errorf("uploaded %v, want nothing", keysOf(got))
			}
		})
	}

	t.Run("no .tf files: refused", func(t *testing.T) {
		r, _ := newTFSyncRig(t)
		r.run("--tf-providers", "--terraform-dir", t.TempDir())
		if r.code == 0 || !strings.Contains(r.stderr, "no .tf files") {
			t.Fatalf("exit %d, stderr %q; want a refusal naming the missing .tf files", r.code, r.stderr)
		}
	})

	t.Run("dry run touches nothing", func(t *testing.T) {
		r, tfDir := newTFSyncRig(t)
		r.run("--tf-providers", "--dry-run", "--terraform-dir", tfDir)
		if r.code != 0 || !strings.Contains(r.stdout, "s3://aerolvm-downloads/tf-providers/") {
			t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
		}
		if strings.Contains(r.logs, "terraform") || strings.Contains(r.logs, "aws ") {
			t.Errorf("dry run ran a tool:\n%s", r.logs)
		}
	})
}

// --tf-providers --check asks Terraform itself to install every provider with
// the public mirror as its only source, and uploads nothing.
func TestMirrorSyncTFProvidersCheck(t *testing.T) {
	for _, tc := range []struct {
		name, wantURL string
		wantOK        bool
	}{
		{"the mirror serves every provider", tfMirrorPublic, true},
		{"it does not", "https://elsewhere.example/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, tfDir := newTFSyncRig(t)
			r.env = append(r.env, "FAKE_TF_WANT_URL="+tc.wantURL)
			r.run("--tf-providers", "--check", "--terraform-dir", tfDir)
			if (r.code == 0) != tc.wantOK {
				t.Fatalf("exit %d, want ok=%v", r.code, tc.wantOK)
			}
			if got := r.uploaded(); len(got) != 0 {
				t.Errorf("--check uploaded %v", keysOf(got))
			}
			if !strings.Contains(r.logs, "init -backend=false -input=false") {
				t.Errorf("--check did not run terraform init without a backend:\n%s", r.logs)
			}
			if !tc.wantOK && !strings.Contains(r.stderr, "--tf-providers with credentials") {
				t.Errorf("a failed check does not say how to fill the mirror:\n%s", r.stderr)
			}
		})
	}
}

func firstLine(s, prefix string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}
