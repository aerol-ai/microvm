package secrets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Server-key rotation (plans/customer-key-custody.md §13, eng D26). The
// server key becomes a ring: every key has an id, a state and a check, and
// exactly one is current. Key id 0 is the key every install starts with;
// its blobs carry no key id. A rotation is staged so no node ever meets a
// blob it cannot open: stage a new key as decrypt-only, promote it once
// every node holds it, reseal every row, retire the old key once no row
// is left on it.

// Ring key states.
const (
	RingStateCurrent = "current"
	RingStateDecrypt = "decrypt"
	RingStateRetired = "retired"
)

// WrappedKeyRingFormat is the wrapped server-key file once it holds a ring.
// A ring of the one legacy key is still written as format 1, so a node that
// never rotates keeps a file older builds read.
const WrappedKeyRingFormat = 2

// KeyRingFileFormat is the version of custody=file's plaintext ring file.
const KeyRingFileFormat = 1

// RingEntry is one key of the ring on disk. With custody=wrapped Wrapped
// holds the key wrapped by the key store; with custody=file Key holds it in
// plaintext. A retired entry keeps only its id, state and check: the record
// of what was retired outlives the key.
type RingEntry struct {
	ID      uint32 `json:"id"`
	State   string `json:"state"`
	Wrapped []byte `json:"wrapped,omitempty"`
	Key     []byte `json:"key,omitempty"`
	Check   []byte `json:"check"`
}

// KeyRingFile is custody=file's ring (SB_CREDENTIAL_KEY_RING_PATH, mode
// 0600). Once it exists it is the whole server key: the legacy key file
// and SB_CREDENTIAL_ENCRYPTION_KEY are only checked against it.
type KeyRingFile struct {
	Format int         `json:"format"`
	Ring   []RingEntry `json:"ring"`
}

// validateRing checks a ring read from disk: unique ids, one current key,
// known states, and bytes only on keys that are not retired (wrapped bytes
// for custody=wrapped, a 32-byte key matching its check for custody=file).
func validateRing(entries []RingEntry, wrapped bool) error {
	if len(entries) == 0 {
		return errors.New("server-key ring is empty")
	}
	seen := map[uint32]bool{}
	currents := 0
	for _, e := range entries {
		if seen[e.ID] {
			return fmt.Errorf("server-key ring: key id %d appears twice", e.ID)
		}
		seen[e.ID] = true
		if len(e.Check) != 16 {
			return fmt.Errorf("server-key ring: key id %d has no check", e.ID)
		}
		switch e.State {
		case RingStateCurrent:
			currents++
		case RingStateDecrypt:
		case RingStateRetired:
			if len(e.Wrapped) != 0 || len(e.Key) != 0 {
				return fmt.Errorf("server-key ring: retired key id %d still holds key bytes", e.ID)
			}
			continue
		default:
			return fmt.Errorf("server-key ring: key id %d has unknown state %q", e.ID, e.State)
		}
		if wrapped {
			if len(e.Wrapped) == 0 || len(e.Key) != 0 {
				return fmt.Errorf("server-key ring: key id %d must hold only its wrapped key", e.ID)
			}
			continue
		}
		if len(e.Key) != 32 || len(e.Wrapped) != 0 || !hmac.Equal(serverKeyCheck(e.Key), e.Check) {
			return fmt.Errorf("server-key ring: key id %d is not a 32-byte key matching its check", e.ID)
		}
	}
	if currents != 1 {
		return fmt.Errorf("server-key ring must have exactly one current key (has %d)", currents)
	}
	return nil
}

// Entries is the file's ring; a format 1 file is the legacy key alone.
func (f WrappedKeyFile) Entries() []RingEntry {
	if f.Format == WrappedKeyRingFormat {
		return append([]RingEntry(nil), f.Ring...)
	}
	return []RingEntry{{ID: 0, State: RingStateCurrent, Wrapped: f.Wrapped, Check: f.Check}}
}

// SetEntries replaces the file's ring. The top-level wrapped key and check
// stay the current key's, so the re-check and every single-key reader keep
// working on a ring file.
func (f *WrappedKeyFile) SetEntries(entries []RingEntry) error {
	if err := validateRing(entries, true); err != nil {
		return err
	}
	cur := currentEntry(entries)
	f.Wrapped, f.Check = cur.Wrapped, cur.Check
	if len(entries) == 1 && cur.ID == 0 {
		f.Format, f.Ring = WrappedKeyFormat, nil
		return nil
	}
	f.Format, f.Ring = WrappedKeyRingFormat, sortedEntries(entries)
	return nil
}

func currentEntry(entries []RingEntry) RingEntry {
	for _, e := range entries {
		if e.State == RingStateCurrent {
			return e
		}
	}
	return RingEntry{}
}

func sortedEntries(entries []RingEntry) []RingEntry {
	out := append([]RingEntry(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// UnwrapRing unwraps every key of f that is not retired. held reports a key
// the Cipher already holds (same id and check): it comes back with a nil
// Key, which SetRing keeps, so a re-read makes no key-store call for it.
func UnwrapRing(ctx context.Context, w DataKeyWrapper, f WrappedKeyFile, held func(id uint32, check []byte) bool) ([]RingKey, error) {
	var keys []RingKey
	for _, e := range f.Entries() {
		if e.State == RingStateRetired {
			continue
		}
		rk := RingKey{ID: e.ID, Current: e.State == RingStateCurrent}
		if held == nil || !held(e.ID, e.Check) {
			key, err := UnwrapServerKey(ctx, w, WrappedKeyFile{Wrapped: e.Wrapped, Check: e.Check})
			if err != nil {
				return nil, fmt.Errorf("server-key ring key %d: %w", e.ID, err)
			}
			rk.Key = key
		}
		keys = append(keys, rk)
	}
	return keys, nil
}

// RingKeys is the ring file's keys that are not retired.
func (f KeyRingFile) RingKeys() []RingKey {
	var keys []RingKey
	for _, e := range f.Ring {
		if e.State != RingStateRetired {
			keys = append(keys, RingKey{ID: e.ID, Key: e.Key, Current: e.State == RingStateCurrent})
		}
	}
	return keys
}

// Entry returns the ring's entry for id.
func (f KeyRingFile) Entry(id uint32) (RingEntry, bool) {
	for _, e := range f.Ring {
		if e.ID == id {
			return e, true
		}
	}
	return RingEntry{}, false
}

// ReadKeyRingFile reads and validates custody=file's ring file.
func ReadKeyRingFile(path string) (KeyRingFile, error) {
	if err := RefuseGroupOtherBits(path); err != nil {
		return KeyRingFile{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return KeyRingFile{}, fmt.Errorf("read server-key ring: %w", err)
	}
	var f KeyRingFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return KeyRingFile{}, fmt.Errorf("server-key ring %s is not valid JSON: %w", path, err)
	}
	if f.Format != KeyRingFileFormat {
		return KeyRingFile{}, fmt.Errorf("server-key ring %s has format %d; this sandboxd reads format %d", path, f.Format, KeyRingFileFormat)
	}
	if err := validateRing(f.Ring, false); err != nil {
		return KeyRingFile{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// WriteKeyRingFile writes the ring file atomically at mode 0600.
func WriteKeyRingFile(path string, f KeyRingFile) error {
	f.Format = KeyRingFileFormat
	if err := validateRing(f.Ring, false); err != nil {
		return err
	}
	f.Ring = sortedEntries(f.Ring)
	unlock, err := lockKeyFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	return writeSecretJSON(path, f, ".key-ring-*")
}

// ReplaceKeyRingFile is WriteKeyRingFile as a compare-and-swap under the
// key-file lock: it writes next only if the file still holds prev (nil:
// the file must not exist yet), else ErrKeyFileChanged.
func ReplaceKeyRingFile(path string, prev *KeyRingFile, next KeyRingFile) error {
	next.Format = KeyRingFileFormat
	if err := validateRing(next.Ring, false); err != nil {
		return err
	}
	next.Ring = sortedEntries(next.Ring)
	unlock, err := lockKeyFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := ReadKeyRingFile(path)
	switch {
	case prev == nil && errors.Is(err, os.ErrNotExist):
	case prev == nil && err == nil:
		return ErrKeyFileChanged
	case err != nil:
		return err
	default:
		a, _ := json.Marshal(cur.Ring)
		b, _ := json.Marshal(sortedEntries(prev.Ring))
		if !bytes.Equal(a, b) {
			return ErrKeyFileChanged
		}
	}
	return writeSecretJSON(path, next, ".key-ring-*")
}

// writeSecretJSON writes v to path atomically at mode 0600: a temp file in
// the same directory, fsync, rename, fsync of the directory.
func writeSecretJSON(path string, v any, pattern string) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return fmt.Errorf("create key temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// NewRingEntry makes a fresh key for StageRingKey. wrap seals it for
// custody=wrapped; nil keeps it in plaintext for custody=file.
func NewRingEntry(ctx context.Context, id uint32, w DataKeyWrapper) (RingEntry, error) {
	key, err := NewServerKey()
	if err != nil {
		return RingEntry{}, err
	}
	e := RingEntry{ID: id, State: RingStateDecrypt, Check: serverKeyCheck(key)}
	if w == nil {
		e.Key = key
		return e, nil
	}
	f, err := WrapServerKey(ctx, w, key, "", "")
	if err != nil {
		return RingEntry{}, err
	}
	e.Wrapped = f.Wrapped
	return e, nil
}

// NextRingID is the id a staged key takes: one past every id the ring has
// ever had, retired ones included, so an id is never reused.
func NextRingID(entries []RingEntry) uint32 {
	var next uint32
	for _, e := range entries {
		if e.ID >= next {
			next = e.ID + 1
		}
	}
	return next
}

// ErrRotationInProgress refuses a stage while another key is decrypt-only:
// one rotation at a time, so "zero rows on the old key" means one key.
var ErrRotationInProgress = errors.New("a rotation is already in progress")

// StageRingKey adds staged (state decrypt) to the ring.
func StageRingKey(entries []RingEntry, staged RingEntry) ([]RingEntry, error) {
	for _, e := range entries {
		if e.State == RingStateDecrypt {
			return nil, fmt.Errorf("%w: key %d is still decrypt-only; promote or retire it first", ErrRotationInProgress, e.ID)
		}
	}
	if staged.ID != NextRingID(entries) || staged.State != RingStateDecrypt {
		return nil, fmt.Errorf("staged key must be id %d in state %s", NextRingID(entries), RingStateDecrypt)
	}
	return append(append([]RingEntry(nil), entries...), staged), nil
}

// PromoteRingKey makes the staged key (the decrypt-only key newer than the
// current one) current; the old current key becomes decrypt-only until it
// is retired. It returns the old and new current ids.
func PromoteRingKey(entries []RingEntry) (out []RingEntry, from, to uint32, err error) {
	cur := currentEntry(entries)
	staged := -1
	for i, e := range entries {
		if e.State == RingStateDecrypt && e.ID > cur.ID {
			staged = i
		}
	}
	if staged < 0 {
		return nil, 0, 0, errors.New("no staged key to promote; run `sandboxd key rotate --stage` first")
	}
	out = append([]RingEntry(nil), entries...)
	for i := range out {
		switch {
		case i == staged:
			out[i].State = RingStateCurrent
		case out[i].State == RingStateCurrent:
			out[i].State = RingStateDecrypt
		}
	}
	return out, cur.ID, out[staged].ID, nil
}

// RetireRingKey retires a decrypt-only key and drops its bytes. Retiring a
// staged key that was never promoted cancels the rotation.
func RetireRingKey(entries []RingEntry, id uint32) ([]RingEntry, error) {
	out := append([]RingEntry(nil), entries...)
	for i, e := range out {
		if e.ID != id {
			continue
		}
		switch e.State {
		case RingStateRetired:
			return nil, fmt.Errorf("key %d is already retired", id)
		case RingStateCurrent:
			return nil, fmt.Errorf("key %d is current; promote another key before retiring it", id)
		}
		out[i] = RingEntry{ID: e.ID, State: RingStateRetired, Check: e.Check}
		return out, nil
	}
	return nil, fmt.Errorf("the ring has no key %d", id)
}

// RingSummary is a ring's ids and states, "0:retired,1:current": what the
// daemon remembers between re-reads to record rotation steps.
func RingSummary(entries []RingEntry) string {
	b := make([]byte, 0, 16*len(entries))
	for i, e := range sortedEntries(entries) {
		if i > 0 {
			b = append(b, ',')
		}
		b = fmt.Appendf(b, "%d:%s", e.ID, e.State)
	}
	return string(b)
}

// ParseRingSummary reads a RingSummary back; malformed parts are skipped.
func ParseRingSummary(s string) map[uint32]string {
	out := map[uint32]string{}
	var id uint32
	var state string
	for len(s) > 0 {
		part := s
		if i := strings.IndexByte(s, ','); i >= 0 {
			part, s = s[:i], s[i+1:]
		} else {
			s = ""
		}
		if n, err := fmt.Sscanf(part, "%d:%s", &id, &state); err == nil && n == 2 {
			out[id] = state
		}
	}
	return out
}

// ErrNotLocalRow is a cluster-secret row whose data key the server key does
// not wrap (a key-store row): a server-key rotation leaves it alone.
var ErrNotLocalRow = errors.New("not a row wrapped by the server key")

// ResealLocalEnvelope moves a local row's data key onto the server key's
// current ring key (§13 step 3). Only WrappedKey changes, so the result is
// the same secret by SameEnvelopeContent. from is the key that opened it;
// changed is false when it was already current.
func ResealLocalEnvelope(sealed []byte, local *Cipher) (out []byte, from uint32, changed bool, err error) {
	env, err := parseEnvelope(sealed)
	if err != nil {
		return nil, 0, false, err
	}
	if WrappedKeyBackend(env.WrappedKey) != "" {
		return nil, 0, false, ErrNotLocalRow
	}
	recipients, binding, err := envelopeBinding(env)
	if err != nil {
		return nil, 0, false, err
	}
	wrapped, from, changed, err := local.Reseal(env.WrappedKey, KeyAADBound(recipients, binding))
	if errors.Is(err, ErrKeyRevoked) {
		return nil, 0, false, err
	}
	if err != nil {
		// An untagged AWS KMS row: the server key does not open it.
		return nil, 0, false, fmt.Errorf("%w: %v", ErrNotLocalRow, err)
	}
	if !changed {
		return sealed, from, false, nil
	}
	env.WrappedKey = wrapped
	out, err = json.Marshal(env)
	if err != nil {
		return nil, from, false, fmt.Errorf("reseal: marshal envelope: %w", err)
	}
	return out, from, true, nil
}

// ErrKeyFileChanged means the server-key file changed between the read an
// edit started from and its write: the daemon's rewrap and `sandboxd key
// rotate` both edit it, and neither may undo the other.
var ErrKeyFileChanged = errors.New("the server-key file changed while it was being edited; run again")

// ReplaceWrappedKeyFile writes next only if the file still holds prev: a
// compare-and-swap on the file's content, re-read just before the write.
func ReplaceWrappedKeyFile(path string, prev, next WrappedKeyFile) error {
	unlock, err := lockKeyFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := ReadWrappedKeyFile(path)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(cur)
	b, _ := json.Marshal(prev)
	if !bytes.Equal(a, b) {
		return ErrKeyFileChanged
	}
	return writeSecretJSON(path, next, ".wrapped-key-*")
}

// LegacyRingEntry is a plaintext key as ring key 0, the current key: the
// ring custody=file starts from when it first rotates.
func LegacyRingEntry(key []byte) RingEntry {
	return RingEntry{ID: 0, State: RingStateCurrent, Key: key, Check: serverKeyCheck(key)}
}

// StaleRingKeys counts f's live keys wrapped under a key-store version
// other than current (the rewrap sweep's view of the server-key file).
func (f WrappedKeyFile) StaleRingKeys(current string) int {
	n := 0
	for _, e := range f.Entries() {
		if e.State != RingStateRetired && WrappedKeyVersion(e.Wrapped) != current {
			n++
		}
	}
	return n
}

// RewrapRing wraps every live key of f again under w's newest key: the same
// keys, ids, states and checks, new wrapped bytes.
func RewrapRing(ctx context.Context, w DataKeyWrapper, f WrappedKeyFile) (WrappedKeyFile, error) {
	entries := f.Entries()
	for i, e := range entries {
		if e.State == RingStateRetired {
			continue
		}
		key, err := UnwrapServerKey(ctx, w, WrappedKeyFile{Wrapped: e.Wrapped, Check: e.Check})
		if err != nil {
			return WrappedKeyFile{}, fmt.Errorf("server-key ring key %d: %w", e.ID, err)
		}
		nf, err := WrapServerKey(ctx, w, key, f.Provider, f.KeyRef)
		if err != nil {
			return WrappedKeyFile{}, err
		}
		entries[i].Wrapped = nf.Wrapped
	}
	out := f
	if err := out.SetEntries(entries); err != nil {
		return WrappedKeyFile{}, err
	}
	return out, nil
}

// WrapRing wraps custody=file's ring with w: the wrapped file a migration to
// custody=wrapped writes when the plaintext key was already rotated.
func WrapRing(ctx context.Context, w DataKeyWrapper, ring KeyRingFile, provider, keyRef string) (WrappedKeyFile, error) {
	entries := make([]RingEntry, 0, len(ring.Ring))
	for _, e := range ring.Ring {
		ne := RingEntry{ID: e.ID, State: e.State, Check: e.Check}
		if e.State != RingStateRetired {
			f, err := WrapServerKey(ctx, w, e.Key, provider, keyRef)
			if err != nil {
				return WrappedKeyFile{}, err
			}
			ne.Wrapped = f.Wrapped
		}
		entries = append(entries, ne)
	}
	out := WrappedKeyFile{Provider: provider, KeyRef: keyRef}
	if err := out.SetEntries(entries); err != nil {
		return WrappedKeyFile{}, err
	}
	return out, nil
}

// UnwrapRingToFile is the rollback of a rotated wrapped key to custody=file:
// the plaintext ring file.
func UnwrapRingToFile(ctx context.Context, w DataKeyWrapper, f WrappedKeyFile) (KeyRingFile, error) {
	out := KeyRingFile{Format: KeyRingFileFormat}
	for _, e := range f.Entries() {
		ne := RingEntry{ID: e.ID, State: e.State, Check: e.Check}
		if e.State != RingStateRetired {
			key, err := UnwrapServerKey(ctx, w, WrappedKeyFile{Wrapped: e.Wrapped, Check: e.Check})
			if err != nil {
				return KeyRingFile{}, fmt.Errorf("server-key ring key %d: %w", e.ID, err)
			}
			ne.Key = key
		}
		out.Ring = append(out.Ring, ne)
	}
	return out, validateRing(out.Ring, false)
}
