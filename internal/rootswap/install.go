package rootswap

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootfolder"
)

func newHash() hash.Hash { return sha256.New() }

// stagedFlags open a staged file for reading without following a link in
// its place, and without blocking: a FIFO the agent left there must not
// hang root.
const stagedFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

// openStage opens the staged folder from / with no link followed. It is
// the agent's folder, so nothing about its owner or mode is checked, and
// nothing is made there: what root takes from it is checked after.
func openStage(dir string) (int, error) {
	return rootfolder.WalkFolder(dir, false, func(string, *unix.Stat_t, bool) error { return nil })
}

// Fingerprint names the staged set as it is now: each file's identity,
// size and change time, read without following a link. It changes when
// any staged file is replaced or written, so the supervisor reads and
// checks a set only after it stayed the same for a while, and never one
// it caught halfway through staging. A missing file is part of the name,
// not an error; a missing folder is one.
func Fingerprint(stageDir string) (string, error) {
	dfd, err := openStage(stageDir)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(dfd) }()
	var b strings.Builder
	for _, n := range []string{BinaryName, ManifestName, SignatureName} {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			b.WriteString("-;")
			continue
		}
		fmt.Fprintf(&b, "%d:%d:%o:%d:%d;", st.Dev, st.Ino, st.Mode, st.Size, st.Mtim.Nano())
	}
	return b.String(), nil
}

// ReadStaged reads the staged manifest and signature and checks them
// (Verify). Nothing of the binary is read.
func ReadStaged(stageDir string, keys []ed25519.PublicKey) (Manifest, error) {
	s, err := ReadStagedSigned(stageDir, keys)
	return s.Manifest, err
}

// Signed is a staged manifest that passed Verify, with the exact bytes the
// signature covers: a VM keeps them beside the helper it installs, so the
// next upgrade knows the running helper's version (CheckNewer) from signed
// bytes too.
type Signed struct {
	Manifest  Manifest
	Raw       []byte
	Signature []byte
}

// ReadStagedSigned is ReadStaged, keeping the bytes it checked.
func ReadStagedSigned(stageDir string, keys []ed25519.PublicKey) (Signed, error) {
	dfd, err := openStage(stageDir)
	if err != nil {
		return Signed{}, err
	}
	defer func() { _ = unix.Close(dfd) }()
	sig, err := readSmall(dfd, SignatureName, maxSignatureSize)
	switch {
	case errors.Is(err, unix.ENOENT):
		return Signed{}, refuse(ReasonUnsigned, "no %s is staged", SignatureName)
	case err != nil:
		return Signed{}, err
	}
	manifest, err := readSmall(dfd, ManifestName, maxManifestSize)
	switch {
	case errors.Is(err, unix.ENOENT):
		return Signed{}, refuse(ReasonBadManifest, "no %s is staged", ManifestName)
	case err != nil:
		return Signed{}, err
	}
	m, err := Verify(keys, manifest, sig)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Manifest: m, Raw: manifest, Signature: sig}, nil
}

// readSmall reads a small staged file: a regular file, not a link, no
// larger than max.
func readSmall(dfd int, name string, max int64) ([]byte, error) {
	f, st, err := openStaged(dfd, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > max {
		return nil, refuse(ReasonNotFile, "%s is %d bytes; at most %d", name, st.Size, max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// openStaged opens a staged file that must be a regular file. ENOENT comes
// back as it is; a link or anything else in its place is a refusal.
func openStaged(dfd int, name string) (*os.File, *unix.Stat_t, error) {
	fd, err := unix.Openat(dfd, name, stagedFlags, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil, err
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EMLINK):
		return nil, nil, refuse(ReasonNotFile, "%s is a link", name)
	case err != nil:
		return nil, nil, refuse(ReasonNotFile, "%s: %v", name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, nil, refuse(ReasonNotFile, "%s is not a regular file (mode %o)", name, st.Mode)
	}
	return os.NewFile(uintptr(fd), name), &st, nil
}

// Installed is a verified copy of a helper in root's own folder.
type Installed struct {
	// Path is the copy, in a folder only root can write: what the
	// supervisor runs.
	Path     string
	Manifest Manifest
}

// copyName is the copy's name: the version for a reader, the hash so two
// builds of one version never share a name.
func copyName(m Manifest) string { return BinaryName + "-" + m.Version + "-" + m.SHA256[:16] }

// Install copies the staged binary into binDir and checks the copy against
// m, which ReadStaged verified (outside review O3):
//
//   - binDir is opened as OpenFolder opens the helper's own folders: root's
//     alone, every folder above it closed or sticky, made where missing
//     through the checked folder above. So once the copy is there, only
//     root can change it.
//   - The staged binary is opened without following a link and must be a
//     regular file; its bytes are copied to a new name in binDir.
//   - The copy, not the staged file, is read back and hashed. A staged file
//     the agent swaps or writes to before or during the copy gives a copy
//     that does not match, and it is removed; one it swaps after cannot
//     change the copy.
//
// The copy is mode 0500 and named for its version and hash.
func Install(stageDir, binDir string, m Manifest) (*Installed, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return nil, fmt.Errorf("root helper copies: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	sfd, err := openStage(stageDir)
	if err != nil {
		return nil, err
	}
	in, st, err := openStaged(sfd, BinaryName)
	_ = unix.Close(sfd)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, refuse(ReasonMissing, "no %s is staged", BinaryName)
	case err != nil:
		return nil, err
	}
	defer in.Close()
	switch {
	case st.Size < m.Size:
		return nil, refuse(ReasonTruncated, "the staged binary is %d bytes; the manifest says %d", st.Size, m.Size)
	case st.Size > m.Size:
		return nil, refuse(ReasonWrongSize, "the staged binary is %d bytes; the manifest says %d", st.Size, m.Size)
	}
	if afterOpen != nil {
		afterOpen()
	}
	tmp, err := rootfolder.TmpName(BinaryName)
	if err != nil {
		return nil, err
	}
	if err := copyIn(bfd, tmp, in, m.Size); err != nil {
		_ = unix.Unlinkat(bfd, tmp, 0)
		return nil, err
	}
	if err := checkCopy(bfd, tmp, m); err != nil {
		_ = unix.Unlinkat(bfd, tmp, 0)
		return nil, err
	}
	name := copyName(m)
	if err := unix.Renameat(bfd, tmp, bfd, name); err != nil {
		_ = unix.Unlinkat(bfd, tmp, 0)
		return nil, fmt.Errorf("root helper copy: %w", err)
	}
	return &Installed{Path: filepath.Join(binDir, name), Manifest: m}, nil
}

// afterOpen, when set, runs once the staged binary is open, before it is
// copied: tests swap the staged file there.
var afterOpen func()

// copyIn writes size bytes of in to a new file tmp in the folder dfd.
func copyIn(dfd int, tmp string, in io.Reader, size int64) error {
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o500)
	if err != nil {
		return fmt.Errorf("root helper copy: %w", err)
	}
	out := os.NewFile(uintptr(fd), tmp)
	n, err := io.Copy(out, io.LimitReader(in, size+1))
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return fmt.Errorf("root helper copy: %w", err)
	case n < size:
		return refuse(ReasonTruncated, "the staged binary gave %d bytes; the manifest says %d", n, size)
	case n > size:
		return refuse(ReasonWrongSize, "the staged binary grew while it was copied")
	}
	return nil
}

// checkCopy reads root's copy back and checks it is m's binary.
func checkCopy(dfd int, tmp string, m Manifest) error {
	fd, err := unix.Openat(dfd, tmp, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("root helper copy: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("root helper copy: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != m.Size || st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("root helper copy: %s is not the file just written (mode %o, %d bytes, uid %d)", tmp, st.Mode, st.Size, st.Uid)
	}
	h := newHash()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("root helper copy: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != m.SHA256 {
		return refuse(ReasonHash, "the staged binary's SHA-256 is %s; the manifest says %s", got, m.SHA256)
	}
	return nil
}

// Remove removes the copy. It sits in root's own folder, so its path
// still names it.
func (i *Installed) Remove() error {
	if err := os.Remove(i.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Sweep removes every copy and half-made copy in binDir but keep: copies
// a supervisor that stopped left behind. The floor stays (FloorName); a
// half-written one goes.
func Sweep(binDir string, keep ...string) error {
	bfd, err := rootfolder.OpenFolder(binDir)
	if err != nil {
		return fmt.Errorf("root helper copies: %w", err)
	}
	defer func() { _ = unix.Close(bfd) }()
	// The handle above may be O_PATH, which cannot list; "." through it
	// is that same folder, opened to read.
	lfd, err := unix.Openat(bfd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(lfd), binDir)
	names, err := d.Readdirnames(-1)
	_ = d.Close()
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		ours := strings.HasPrefix(n, BinaryName+"-") || rootfolder.IsTmpName(n, BinaryName) || rootfolder.IsTmpName(n, FloorName)
		if !ours || contains(keep, filepath.Join(binDir, n)) {
			continue
		}
		if err := unix.Unlinkat(bfd, n, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Stage is the agent's side: it copies the helper, its manifest and its
// signature from fromDir (the agent image's copy of the release) into
// stageDir. Each is written whole under a new name first; then the three
// are renamed into place one after another, so the supervisor never reads
// a file half written, and the set is mixed only for the moment between
// the renames. The supervisor judges a set only once it has stayed the
// same for a whole tick, so it never judges that moment.
func Stage(fromDir, stageDir string) error {
	names := []string{BinaryName, SignatureName, ManifestName}
	var tmps []string
	clean := func() {
		for _, t := range tmps {
			_ = os.Remove(t)
		}
	}
	for _, n := range names {
		tmp, err := stageOne(filepath.Join(fromDir, n), stageDir, n)
		if err != nil {
			clean()
			return fmt.Errorf("stage %s: %w", n, err)
		}
		tmps = append(tmps, tmp)
	}
	for i, n := range names {
		if err := os.Rename(tmps[i], filepath.Join(stageDir, n)); err != nil {
			clean()
			return fmt.Errorf("stage %s: %w", n, err)
		}
	}
	return nil
}

// stageOne writes a copy of from to a new name in stageDir and returns it.
func stageOne(from, stageDir, name string) (string, error) {
	in, err := os.Open(from)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp, err := rootfolder.TmpName(name)
	if err != nil {
		return "", err
	}
	tmpPath := filepath.Join(stageDir, tmp)
	out, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}
