package rootswap

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// The floor: root never runs a helper older than the one it ran (CheckNewer).
// The supervisor knows the helper it runs while it runs, but a restart of
// its container starts it with nothing in memory, and the agent can stage
// any helper a release ever signed. So the supervisor writes the signed
// manifest of each helper it runs, and its signature, to FloorName and
// FloorSigName in its own folder of copies before that helper starts, and
// reads them back when it starts. The folder is root's alone
// (rootfolder.OpenFolder), so the agent can neither write the floor nor put
// an older one in its place. On Kubernetes it sits on a volume only the
// runtime container mounts, which outlives a restart of that container and
// ends with the pod.
//
// The floor binds by its manifest alone, signature or not: it is root's own
// record, in root's own folder, and a runtime image whose release keys
// changed still holds to the floor its last helper left. The signature is
// for Resume: after a restart, the floor's own copy, still in the folder,
// runs again only once its manifest verifies against the keys of the image
// that runs now and the copy is still that binary. So a worker whose agent
// went back to an older release keeps the helper it ran, as it did before
// the restart.

// FloorName is the floor's file in the supervisor's folder of copies: the
// signed manifest's exact bytes. FloorSigName beside it is the signature.
// Sweep keeps both: they are no copy.
const (
	FloorName    = BinaryName + ".floor"
	FloorSigName = FloorName + ".sig"
)

// WriteFloor records s as the floor in binDir. Each file is written whole
// under a new name, synced and renamed over the last one, the signature
// first, then the folder is synced. A crash between the two renames leaves
// a signature that does not verify over the floor beside it: the floor
// still binds, and Resume refuses the pair.
func WriteFloor(binDir string, s Signed) error {
	m, err := parseManifest(s.Raw)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	if m != s.Manifest {
		return errors.New("root helper floor: the bytes given are not the manifest given")
	}
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	if len(s.Signature) == 0 {
		// No signature: none from an earlier floor may sit beside it.
		if err := unix.Unlinkat(bfd, FloorSigName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("root helper floor: %w", err)
		}
	} else if err := replaceFile(bfd, FloorSigName, s.Signature); err != nil {
		return err
	}
	if err := replaceFile(bfd, FloorName, s.Raw); err != nil {
		return err
	}
	return syncFolder(bfd)
}

// replaceFile writes data to name in the folder dfd: whole under a new
// name, synced, then renamed over name.
func replaceFile(dfd int, name string, data []byte) error {
	tmp, err := rootfolder.TmpName(name)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("root helper floor: %w", err)
	}
	return nil
}

// syncFolder syncs the folder dfd names, so a rename in it outlives a crash.
// The handle may be O_PATH, which cannot sync; "." through it is the same
// folder, opened to read.
func syncFolder(dfd int) error {
	fd, err := unix.Openat(dfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("root helper floor: %w", err)
	}
	return nil
}

// ReadFloor is the floor in binDir: the signed manifest of the helper root
// ran last, with its signature when one was kept (a floor written before
// signatures were kept has none), or nil when root has run none there yet.
// A floor that is there but cannot be read, or is not a whole manifest, is
// an error: the caller then runs no staged helper, as it cannot tell which
// ones are older.
func ReadFloor(binDir string) (*Signed, error) {
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return nil, fmt.Errorf("root helper floor: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	raw, err := readRootFile(bfd, binDir, FloorName, maxManifestSize)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case err != nil:
		return nil, err
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("root helper floor %s: %w", filepath.Join(binDir, FloorName), err)
	}
	sig, err := readRootFile(bfd, binDir, FloorSigName, maxSignatureSize)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	return &Signed{Manifest: m, Raw: raw, Signature: sig}, nil
}

// readRootFile reads name in the folder dfd: a regular file this process's
// user owns, not a link, no larger than max. ENOENT comes back as it is.
func readRootFile(dfd int, dir, name string, max int64) ([]byte, error) {
	path := filepath.Join(dir, name)
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("root helper floor %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("root helper floor: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("root helper floor %s is not a regular file (mode %o)", path, st.Mode)
	case st.Uid != uint32(os.Geteuid()):
		return nil, fmt.Errorf("root helper floor %s belongs to uid %d", path, st.Uid)
	case st.Size > max:
		return nil, fmt.Errorf("root helper floor %s is %d bytes; at most %d", path, st.Size, max)
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, fmt.Errorf("root helper floor: %w", err)
	}
	return data, nil
}

// Resume is the floor's own copy in binDir, ready to run again after a
// restart: the floor's signature verifies over its manifest against keys,
// the keys of the image that runs now (Verify, for this machine), and the
// copy named for that manifest is still that binary, a regular file of
// root's of the manifest's size and SHA-256 (checkCopy). Anything else is
// an error, and nothing runs from the folder until a staged helper, not
// older than the floor, is installed there again.
func Resume(binDir string, keys []ed25519.PublicKey, f Signed) (*Installed, error) {
	if len(f.Signature) == 0 {
		return nil, refuse(ReasonUnsigned, "the floor keeps no signature")
	}
	m, err := Verify(keys, f.Raw, f.Signature)
	if err != nil {
		return nil, err
	}
	if m != f.Manifest {
		return nil, refuse(ReasonBadManifest, "the floor's manifest is not the one its bytes hold")
	}
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return nil, fmt.Errorf("root helper copies: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	name := copyName(m)
	if err := checkCopy(bfd, name, m); err != nil {
		return nil, err
	}
	return &Installed{Path: filepath.Join(binDir, name), Manifest: m, Raw: bytes.Clone(f.Raw), Signature: bytes.Clone(f.Signature)}, nil
}
