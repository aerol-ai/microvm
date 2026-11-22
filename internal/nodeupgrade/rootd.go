package nodeupgrade

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/aerol-ai/microvm/internal/rootswap"
)

// The root helper on a VM in privilege mode split (plans/security-gaps-m1-
// m4.md §3.3 "Upgrades", M1 PR 10). aerolvm-rootd.service runs the same
// signed helper the Kubernetes supervisor runs, and the upgrade checks the
// same signature, with the same code (internal/rootswap): a release signs
// the helper's manifest, the manifest names the binary's SHA-256, and root
// installs only a copy it made in a folder of its own and checked against
// that manifest. Nothing the agent writes can make root run an unsigned or
// older helper.
//
// A release ships three files per platform: aerolvm-rootd_<os>_<arch>, its
// .manifest and its .sig. An upgrade that carries one carries all three.
// They are installed in RootdDir under rootswap's fixed names, and the
// manifest and signature stay beside the binary: the next upgrade reads the
// running helper's version from them (rootswap.CheckNewer).

// Roles of the helper's three files.
const (
	roleRootd         = rootswap.BinaryName
	roleRootdManifest = rootswap.ManifestName
	roleRootdSig      = rootswap.SignatureName
)

// DefaultRootdDir is where install.sh puts the helper: a folder only root
// can write (rootswap.Install checks it), outside --install-prefix so its
// verified copies never land on PATH.
const DefaultRootdDir = "/usr/local/lib/aerolvm-rootd"

// rootdUnit is the helper's systemd unit on a VM.
const rootdUnit = "aerolvm-rootd"

// rootdAssetRe is a release asset of the helper: an optional "<tag>_"
// prefix, the binary, an optional OS and CPU type, and .manifest or .sig.
var rootdAssetRe = regexp.MustCompile(`^(?:v[0-9][A-Za-z0-9.+-]*_)?aerolvm-rootd(?:_([a-z0-9]+)_([a-z0-9]+))?(\.manifest|\.sig)?$`)

// rootdRoleOf maps a helper asset to its role; ok is false for any other
// asset.
func rootdRoleOf(asset, goos, goarch string) (role string, ok bool, err error) {
	m := rootdAssetRe.FindStringSubmatch(asset)
	if m == nil {
		return "", false, nil
	}
	if m[1] != "" && (m[1] != goos || !archMatches(m[2], goarch)) {
		return "", true, fmt.Errorf("%s is built for %s_%s, and this node is %s_%s", asset, m[1], m[2], goos, goarch)
	}
	return rootswap.BinaryName + m[3], true, nil
}

// isRootdRole reports whether role is one of the helper's files.
func isRootdRole(role string) bool {
	return role == roleRootd || role == roleRootdManifest || role == roleRootdSig
}

// checkRootdSet refuses a request that names some of the helper's files
// but not all three: the binary is checked against the signed manifest,
// so neither goes without the other.
func checkRootdSet(seen map[string]string) error {
	n := 0
	for _, r := range []string{roleRootd, roleRootdManifest, roleRootdSig} {
		if _, ok := seen[r]; ok {
			n++
		}
	}
	if n != 0 && n != 3 {
		return usageErr("--sha256 names %d of the root helper's 3 files; give aerolvm-rootd, its .manifest and its .sig together", n)
	}
	return nil
}

// releaseKeys are the keys a helper must be signed with; tests set their
// own.
var releaseKeys = rootswap.ReleaseKeys

// RunningRootHelper is the manifest of the helper installed in dir, or nil
// when there is none or what is there cannot be vouched for: its manifest
// must be signed with keys and name the installed binary's SHA-256.
func RunningRootHelper(dir string, keys []ed25519.PublicKey) *rootswap.Manifest {
	raw, err := os.ReadFile(filepath.Join(dir, rootswap.ManifestName))
	if err != nil {
		return nil
	}
	sig, err := os.ReadFile(filepath.Join(dir, rootswap.SignatureName))
	if err != nil {
		return nil
	}
	m, err := rootswap.Verify(keys, raw, sig)
	if err != nil {
		return nil
	}
	if sum, err := fileSHA256(filepath.Join(dir, rootswap.BinaryName)); err != nil || sum != m.SHA256 {
		return nil
	}
	return &m
}

// verifyRootHelper checks the helper staged in stageDir, under rootswap's
// fixed names (rootswap.ReadStagedSigned), against the release keys; refuses
// one older than the helper running from dir unless allowOlder; and copies
// the binary into dir and checks the copy (rootswap.Install). The copy is
// what gets installed, never the staged file.
func verifyRootHelper(stageDir, dir string, allowOlder bool) (*rootswap.Installed, rootswap.Signed, error) {
	keys, err := releaseKeys()
	if err != nil {
		return nil, rootswap.Signed{}, err
	}
	signed, err := rootswap.ReadStagedSigned(stageDir, keys)
	if err != nil {
		return nil, rootswap.Signed{}, fmt.Errorf("root helper: %w", err)
	}
	if !allowOlder {
		if err := rootswap.CheckNewer(signed.Manifest, RunningRootHelper(dir, keys)); err != nil {
			return nil, rootswap.Signed{}, fmt.Errorf("root helper: %w", err)
		}
	}
	inst, err := rootswap.Install(stageDir, dir, signed.Manifest)
	if err != nil {
		return nil, rootswap.Signed{}, fmt.Errorf("root helper: %w", err)
	}
	return inst, signed, nil
}

// RootHelperResult is what InstallRootHelper did.
type RootHelperResult struct {
	Manifest rootswap.Manifest
	// Changed is false when that helper was already installed.
	Changed bool
}

// InstallRootHelper installs the signed helper in fromDir (rootswap's
// fixed names) into dir, with its manifest and signature beside it: the
// path install.sh takes on a fresh node or a node switched to privilege
// mode split (`sandboxd upgrade root-helper`). fromDir must be root's and
// closed to others, as install.sh's temporary folder is, so what was
// checked is what is installed. The old files stay as *.prev. allowOlder
// skips the downgrade check (a rollback).
func InstallRootHelper(fromDir, dir string, allowOlder bool) (RootHelperResult, error) {
	if err := checkRootOnlyFolder(fromDir); err != nil {
		return RootHelperResult{}, err
	}
	inst, signed, err := verifyRootHelper(fromDir, dir, allowOlder)
	if err != nil {
		return RootHelperResult{}, err
	}
	defer func() { _ = rootswap.Sweep(dir) }()
	res := RootHelperResult{Manifest: signed.Manifest}
	cur, _ := fileSHA256(filepath.Join(dir, rootswap.BinaryName))
	curRaw, _ := os.ReadFile(filepath.Join(dir, rootswap.ManifestName))
	curSig, _ := os.ReadFile(filepath.Join(dir, rootswap.SignatureName))
	if cur == signed.Manifest.SHA256 && bytes.Equal(curRaw, signed.Raw) && bytes.Equal(curSig, signed.Signature) {
		return res, nil
	}
	// Manifest and signature first, the binary last: a run stopped half
	// way leaves a manifest that does not name the installed binary, which
	// RunningRootHelper then trusts no more than no manifest at all.
	for _, f := range []struct {
		name string
		data []byte
	}{{rootswap.ManifestName, signed.Raw}, {rootswap.SignatureName, signed.Signature}} {
		tmp := filepath.Join(dir, "."+f.name+".verified")
		if err := writeFileAtomic(tmp, f.data, 0o644); err != nil {
			return res, err
		}
		err := swapIn(tmp, filepath.Join(dir, f.name))
		_ = os.Remove(tmp)
		if err != nil {
			return res, err
		}
		_ = os.Chmod(filepath.Join(dir, f.name), 0o644) // data, not a program
	}
	if err := swapIn(inst.Path, filepath.Join(dir, rootswap.BinaryName)); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// checkRootOnlyFolder refuses a folder anyone but root (or, in tests, this
// process's user) owns or can write, or that a link leads to.
func checkRootOnlyFolder(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("root helper: %s: want an absolute path", dir)
	}
	dir = filepath.Clean(dir)
	owner := uint32(os.Geteuid())
	for at := dir; ; at = filepath.Dir(at) {
		st, err := os.Lstat(at)
		if err != nil {
			return fmt.Errorf("root helper: %w", err)
		}
		uid, mode := statOwner(st)
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("root helper: %s is a link", at)
		case !st.IsDir():
			return fmt.Errorf("root helper: %s is not a folder", at)
		case uid != 0 && uid != owner:
			return fmt.Errorf("root helper: %s belongs to uid %d; the staged helper must sit in root's own folder", at, uid)
		case mode&0o022 != 0 && !(at != dir && mode&os.ModeSticky != 0):
			return fmt.Errorf("root helper: %s can be written by others", at)
		}
		if at == "/" {
			return nil
		}
	}
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// errSplitStateDir refuses an upgrade on a privilege mode split node whose
// upgrade folder is inside sandboxd's data folder: sandboxd's user can
// write there, and root installs from it.
var errSplitStateDir = errors.New("this node runs in privilege mode split, and its upgrade folder is inside sandboxd's data folder, which sandboxd's user can write; set SB_UPGRADE_STATE_DIR to a folder of root's (install.sh --privilege-mode split sets /var/lib/aerolvm-upgrade)")

// statOwner is a file's owner and mode bits.
func statOwner(fi os.FileInfo) (uint32, os.FileMode) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, fi.Mode()
	}
	return ^uint32(0), fi.Mode()
}
