package identitywire

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strconv"
	"strings"
	"time"
)

// An API token (plans/identity-and-access.md §5.4) is
//
//	avm_<id:12>_<secret:43>_<crc:6>
//
// id is 12 base62 characters: the lookup key, and with the tok_ prefix the
// token's public id (the audit caller id, the id GET /v1/tokens lists and
// DELETE /v1/tokens/{id} takes). secret is 32 random bytes in unpadded
// base64url: 256 bits, so a fast hash is enough and only SHA-256(secret) is
// ever stored. crc is CRC-32 (IEEE) of everything before it, in 6 base62
// characters. It lets sandboxd refuse a mistyped or forged token before any
// lookup, and lets secret scanners confirm a match offline (the GitHub
// token pattern).
//
// The secret's alphabet contains '_', so the token is parsed by position,
// never by splitting on '_'.
const (
	// APITokenPrefix starts every API token; secret scanners key on it.
	APITokenPrefix = "avm_"
	// APITokenIDPrefix starts every token's public id.
	APITokenIDPrefix = "tok_"
	// APITokenLength is the length of every well-formed token.
	APITokenLength = len(APITokenPrefix) + idLen + 1 + secretLen + 1 + crcLen

	idLen     = 12
	secretLen = 43 // base64.RawURLEncoding of 32 bytes
	crcLen    = 6
	idStart   = len(APITokenPrefix)
	secretSep = idStart + idLen
	secretOff = secretSep + 1
	crcSep    = secretOff + secretLen
	crcOff    = crcSep + 1
)

// APITokenPattern matches a well-formed token, for secret scanners. A match
// is a real token only if its checksum also holds (ParseAPIToken).
const APITokenPattern = `avm_[0-9A-Za-z]{12}_[0-9A-Za-z_-]{43}_[0-9A-Za-z]{6}`

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ErrMalformedAPIToken is any bearer with the avm_ prefix that is not a
// well-formed token: wrong length, a character outside its alphabet, or a
// checksum that does not hold.
var ErrMalformedAPIToken = errors.New("identitywire: malformed API token")

// APIToken is one token, split into its public id and its secret.
//
// String redacts the secret, so a token printed by accident (a %v in a log
// line) never leaks it. Plaintext is the only way to get the whole token.
type APIToken struct {
	// ID is the public id: "tok_" and the token's 12-character id.
	ID string
	// Secret is the 43-character secret. Only SecretHash is ever stored.
	Secret string
}

// NewAPIToken mints a token from r (crypto/rand when nil).
func NewAPIToken(r io.Reader) (APIToken, error) {
	if r == nil {
		r = rand.Reader
	}
	id, err := randomBase62(r, idLen)
	if err != nil {
		return APIToken{}, fmt.Errorf("identitywire: token id: %w", err)
	}
	var raw [32]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return APIToken{}, fmt.Errorf("identitywire: token secret: %w", err)
	}
	return APIToken{ID: APITokenIDPrefix + id, Secret: base64.RawURLEncoding.EncodeToString(raw[:])}, nil
}

// Plaintext is the whole token, checksum included: what the caller sends as
// its bearer. sandboxd returns it once, at create, and never stores it.
func (t APIToken) Plaintext() string {
	body := APITokenPrefix + strings.TrimPrefix(t.ID, APITokenIDPrefix) + "_" + t.Secret
	return body + "_" + checksum(body)
}

// String is the token with its secret redacted.
func (t APIToken) String() string {
	return APITokenPrefix + strings.TrimPrefix(t.ID, APITokenIDPrefix) + "_[REDACTED]"
}

// GoString redacts too, so %#v is as safe as %v.
func (t APIToken) GoString() string { return "identitywire.APIToken{" + t.String() + "}" }

// SecretHash is SHA-256 of the secret, the only form sandboxd keeps.
func (t APIToken) SecretHash() [32]byte { return HashAPITokenSecret(t.Secret) }

// HashAPITokenSecret is SHA-256 of a token secret.
func HashAPITokenSecret(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

// LooksLikeAPIToken reports whether bearer claims to be an API token. Any
// bearer with the prefix is decided by the token authenticator, malformed or
// not, so a mistyped token gets the token's own refusal reason.
func LooksLikeAPIToken(bearer string) bool { return strings.HasPrefix(bearer, APITokenPrefix) }

// ParseAPIToken checks a token's shape and checksum. It does no lookup: a
// token it accepts may still be unknown, revoked or expired.
func ParseAPIToken(s string) (APIToken, error) {
	if len(s) != APITokenLength || !strings.HasPrefix(s, APITokenPrefix) || s[secretSep] != '_' || s[crcSep] != '_' {
		return APIToken{}, ErrMalformedAPIToken
	}
	id, secret, crc := s[idStart:secretSep], s[secretOff:crcSep], s[crcOff:]
	if !isBase62(id) || !isBase62(crc) || !canonicalSecret(secret) {
		return APIToken{}, ErrMalformedAPIToken
	}
	if crc != checksum(s[:crcSep]) {
		return APIToken{}, ErrMalformedAPIToken
	}
	return APIToken{ID: APITokenIDPrefix + id, Secret: secret}, nil
}

// ValidAPITokenID reports whether id is a well-formed public token id
// ("tok_" and 12 base62 characters).
func ValidAPITokenID(id string) bool {
	rest, ok := strings.CutPrefix(id, APITokenIDPrefix)
	return ok && len(rest) == idLen && isBase62(rest)
}

// APITokenIDFrom returns the public id a revoke should name, given either
// the id itself or a whole token (people paste the token they want gone).
func APITokenIDFrom(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if ValidAPITokenID(s) {
		return s, true
	}
	if t, err := ParseAPIToken(s); err == nil {
		return t.ID, true
	}
	return "", false
}

// Name rules (plans/identity-and-access.md §5.4, CEO review finding 3.6).
// They keep names out of the way of logs, 403 hints and the access-review
// report, which print them verbatim.
const (
	MaxTokenNameLen = 64
	MaxTeamNameLen  = 63
)

// ValidTokenName reports whether name is 1 to 64 characters of A-Z, a-z,
// 0-9, '.', '_' and '-'.
func ValidTokenName(name string) bool {
	if name == "" || len(name) > MaxTokenNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// ValidTeamName reports whether team is 1 to 63 characters of a-z, 0-9 and
// '-'. "*" (every team) is not a team name; callers check it separately.
func ValidTeamName(team string) bool {
	if team == "" || len(team) > MaxTeamNameLen {
		return false
	}
	for i := 0; i < len(team); i++ {
		c := team[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// ParseTokenTTL reads a token lifetime: a Go duration ("720h", "1h30m") or a
// whole number of days ("90d"). It must be positive.
func ParseTokenTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok && days != "" && !strings.ContainsAny(days, "hms.") {
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n <= 0 || n > int64(maxTTLDays) {
			return 0, fmt.Errorf("identitywire: %q is not a positive number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("identitywire: %q is not a positive lifetime; give one like 90d or 720h", s)
	}
	return d, nil
}

// maxTTLDays keeps a day count far from overflowing a time.Duration.
const maxTTLDays = 100 * 365

func checksum(body string) string {
	sum := uint64(crc32.ChecksumIEEE([]byte(body)))
	var out [crcLen]byte
	for i := crcLen - 1; i >= 0; i-- {
		out[i] = base62Alphabet[sum%62]
		sum /= 62
	}
	return string(out[:])
}

// randomBase62 draws n uniform base62 characters, rejecting bytes >= 248 so
// no character is more likely than another.
func randomBase62(r io.Reader, n int) (string, error) {
	out := make([]byte, 0, n)
	var buf [32]byte
	for len(out) < n {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b >= 248 {
				continue
			}
			out = append(out, base62Alphabet[b%62])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isBase62(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

// canonicalSecret reports whether s is the one unpadded base64url encoding
// of 32 bytes. Strict decoding refuses non-zero trailing bits, so no two
// strings decode to the same secret.
func canonicalSecret(s string) bool {
	if len(s) != secretLen {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(raw) == 32
}
