package cloudidentity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// TokenLifetime is how long a token is valid (point 7). A stolen token
	// gives its role for at most this long (point 2).
	TokenLifetime = time.Hour
	// NotBeforeSkew backdates nbf so a cloud whose clock runs behind ours
	// still accepts a fresh token (point 7).
	NotBeforeSkew = 60 * time.Second
	// DefaultAudience is the AWS STS audience: AWS is the first target (Q2).
	DefaultAudience = "sts.amazonaws.com"
	// DiscoveryPath and JWKSPath are served at the issuer's root, where
	// every cloud looks for them.
	DiscoveryPath = "/.well-known/openid-configuration"
	JWKSPath      = "/.well-known/jwks.json"
	// TokenDir and TokenFile are where toolboxd writes the token inside the
	// sandbox.
	TokenDir  = "/run/aerolvm/identity"
	TokenFile = TokenDir + "/token"
	// MaxTokenBytes bounds a token on the wire to toolboxd.
	MaxTokenBytes = 16 << 10
)

// The environment a sandbox with an identity gets (D1.6). Each cloud SDK
// finds the token through its own variable, with no code change inside.
const (
	EnvTokenFile      = "AEROLVM_IDENTITY_TOKEN_FILE"
	EnvAWSTokenFile   = "AWS_WEB_IDENTITY_TOKEN_FILE"
	EnvAWSRoleARN     = "AWS_ROLE_ARN"
	EnvAzureTokenFile = "AZURE_FEDERATED_TOKEN_FILE"
	EnvAzureClientID  = "AZURE_CLIENT_ID"
	EnvAzureTenantID  = "AZURE_TENANT_ID"
)

var (
	// ErrInvalid is a malformed identity request or role tag (400).
	ErrInvalid = errors.New("invalid identity")
	// ErrIssuerURL is a bad SB_IDENTITY_ISSUER_URL.
	ErrIssuerURL = errors.New("SB_IDENTITY_ISSUER_URL must be an https URL with no path, query or fragment")
)

// ValidateIssuerURL returns the canonical issuer (no trailing slash). The
// clouds fetch <issuer>/.well-known/openid-configuration anonymously over
// public HTTPS and Azure compares iss byte for byte, so it must be HTTPS,
// carry a host, and have no path: the documents are served at the root.
func ValidateIssuerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("%w (got %q)", ErrIssuerURL, raw)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// Discovery is the OIDC discovery document of issuer. The clouds read only
// issuer, jwks_uri and the algorithms; the rest is what OIDC discovery
// requires so a strict client accepts it.
func Discovery(issuer string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + JWKSPath,
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{Algorithm},
		"claims_supported":                      []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "sandbox", "team", "role"},
	})
}

var (
	roleTagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	// awsRoleARNRe accepts the partitions' role ARNs; IAM paths are allowed.
	awsRoleARNRe = regexp.MustCompile(`^arn:aws(-cn|-us-gov|-iso|-iso-b)?:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	uuidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// ValidateRoleTag accepts 1-63 characters of a-z, 0-9, '-' and '_',
// starting with a letter or digit. No ':' can appear, so the tag cannot
// extend the subject past its own field.
func ValidateRoleTag(tag string) error {
	if !roleTagRe.MatchString(tag) {
		return fmt.Errorf("%w: role_tag %q: want 1 to 63 characters of a-z, 0-9, '-' and '_', starting with a letter or digit", ErrInvalid, tag)
	}
	return nil
}

// ValidMinRole reports whether r may be a role tag's minimum caller role:
// runner or admin, the two roles that can create a sandbox at all (viewer
// and auditor cannot). runner is the role the design calls "developer".
func ValidMinRole(r string) bool { return r == "runner" || r == "admin" }

// ValidateAudience accepts 1-256 printable ASCII characters with no space.
// The audience is the sandbox's own choice: it does not take part in the
// trust decision on our side, only the cloud's.
func ValidateAudience(aud string) error {
	if aud == "" || len(aud) > 256 {
		return fmt.Errorf("%w: audience must be 1 to 256 characters", ErrInvalid)
	}
	for _, r := range aud {
		if r <= ' ' || r >= 0x7f {
			return fmt.Errorf("%w: audience must be printable ASCII with no spaces", ErrInvalid)
		}
	}
	return nil
}

// Request is the create option (D1.6).
type Request struct {
	RoleTag       string `json:"role_tag"`
	Audience      string `json:"audience,omitempty"`
	AWSRoleARN    string `json:"aws_role_arn,omitempty"`
	AzureClientID string `json:"azure_client_id,omitempty"`
	AzureTenantID string `json:"azure_tenant_id,omitempty"`
}

// Normalize trims every field and fills the default audience.
func (r Request) Normalize() Request {
	r.RoleTag = strings.TrimSpace(r.RoleTag)
	r.Audience = strings.TrimSpace(r.Audience)
	if r.Audience == "" {
		r.Audience = DefaultAudience
	}
	r.AWSRoleARN = strings.TrimSpace(r.AWSRoleARN)
	r.AzureClientID = strings.TrimSpace(r.AzureClientID)
	r.AzureTenantID = strings.TrimSpace(r.AzureTenantID)
	return r
}

// Validate checks a normalized request. The Azure ids come as a pair: one
// without the other gives an SDK half a configuration.
func (r Request) Validate() error {
	if err := ValidateRoleTag(r.RoleTag); err != nil {
		return err
	}
	if err := ValidateAudience(r.Audience); err != nil {
		return err
	}
	if r.AWSRoleARN != "" && !awsRoleARNRe.MatchString(r.AWSRoleARN) {
		return fmt.Errorf("%w: aws_role_arn %q is not an IAM role ARN", ErrInvalid, r.AWSRoleARN)
	}
	if (r.AzureClientID == "") != (r.AzureTenantID == "") {
		return fmt.Errorf("%w: azure_client_id and azure_tenant_id go together", ErrInvalid)
	}
	if r.AzureClientID != "" && (!uuidRe.MatchString(r.AzureClientID) || !uuidRe.MatchString(r.AzureTenantID)) {
		return fmt.Errorf("%w: azure_client_id and azure_tenant_id must be GUIDs", ErrInvalid)
	}
	return nil
}

// Env is the environment the request gives the sandbox.
func (r Request) Env() map[string]string {
	env := map[string]string{EnvTokenFile: TokenFile}
	if r.AWSRoleARN != "" {
		env[EnvAWSTokenFile] = TokenFile
		env[EnvAWSRoleARN] = r.AWSRoleARN
	}
	if r.AzureClientID != "" {
		env[EnvAzureTokenFile] = TokenFile
		env[EnvAzureClientID] = r.AzureClientID
		env[EnvAzureTenantID] = r.AzureTenantID
	}
	return env
}

// operatorSubject is the subject owner of a sandbox the operator namespace
// (owner ref "") holds. No team name or escaped account key can equal it.
const operatorSubject = "operator"

// SubjectOwner is the owner part of the subject and the team claim for an
// owner ref. A team (owner "team:<name>", names are a-z, 0-9 and '-') reads
// "team:<name>"; the operator namespace (owner "") reads "operator"; any
// other owner (a managed account key) reads "account:<key>" with every byte
// outside A-Z, a-z, 0-9, '.' and '-' percent-escaped. The three forms
// cannot overlap and escaping is one-to-one, so distinct owners never share
// a subject (point 6).
func SubjectOwner(ownerRef string) (owner, team string) {
	if ownerRef == "" {
		return operatorSubject, ""
	}
	if name, ok := strings.CutPrefix(ownerRef, "team:"); ok && validTeamName(name) {
		return "team:" + name, name
	}
	return "account:" + escapeOwner(ownerRef), ""
}

// Subject is the sub claim: what a customer's trust policy matches (D1.4).
func Subject(ownerRef, roleTag string) string {
	owner, _ := SubjectOwner(ownerRef)
	return owner + ":role:" + roleTag
}

func validTeamName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func escapeOwner(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// Claims is the token's claim set (D1.4).
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`
	Sandbox   string `json:"sandbox"`
	Team      string `json:"team,omitempty"`
	Role      string `json:"role"`
}

// Token is a signed token and what the audit record names (D1.10). Raw is
// the bearer credential: it goes to toolboxd and nowhere else.
type Token struct {
	Raw    string
	KeyID  string
	Claims Claims
}

// Expires is the token's exp.
func (t Token) Expires() time.Time { return time.Unix(t.Claims.Expiry, 0).UTC() }

// Signer signs with one key.
type Signer struct {
	KeyID string
	Key   *rsa.PrivateKey
}

// IssueRequest is what one token says.
type IssueRequest struct {
	Issuer    string
	OwnerRef  string
	SandboxID string
	RoleTag   string
	Audience  string
	Now       time.Time
	// Rand is the jti source; nil is crypto/rand.
	Rand io.Reader
}

// Issue signs a token for one sandbox.
func (s Signer) Issue(req IssueRequest) (Token, error) {
	if s.Key == nil || s.KeyID == "" {
		return Token{}, errors.New("cloudidentity: no signing key")
	}
	if req.Issuer == "" || req.SandboxID == "" {
		return Token{}, errors.New("cloudidentity: issuer and sandbox are required")
	}
	if err := ValidateRoleTag(req.RoleTag); err != nil {
		return Token{}, err
	}
	if err := ValidateAudience(req.Audience); err != nil {
		return Token{}, err
	}
	src := req.Rand
	if src == nil {
		src = rand.Reader
	}
	var jti [16]byte
	if _, err := io.ReadFull(src, jti[:]); err != nil {
		return Token{}, fmt.Errorf("cloudidentity: token id: %w", err)
	}
	now := req.Now.UTC()
	_, team := SubjectOwner(req.OwnerRef)
	claims := Claims{
		Issuer:    req.Issuer,
		Subject:   Subject(req.OwnerRef, req.RoleTag),
		Audience:  req.Audience,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-NotBeforeSkew).Unix(),
		Expiry:    now.Add(TokenLifetime).Unix(),
		ID:        hex.EncodeToString(jti[:]),
		Sandbox:   req.SandboxID,
		Team:      team,
		Role:      req.RoleTag,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return Token{}, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), s.KeyID))
	if err != nil {
		return Token{}, fmt.Errorf("cloudidentity: signer: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return Token{}, fmt.Errorf("cloudidentity: sign: %w", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		return Token{}, fmt.Errorf("cloudidentity: serialize: %w", err)
	}
	return Token{Raw: raw, KeyID: s.KeyID, Claims: claims}, nil
}

// Verify checks raw against a JWKS document and returns its claims. sandboxd
// never needs it on the request path (only the sandbox receives a token);
// tests, the cluster check that a token one node signed verifies with the
// JWKS another node serves, and the live suite use it.
func Verify(raw string, jwks []byte, now time.Time) (Claims, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &set); err != nil {
		return Claims{}, fmt.Errorf("cloudidentity: jwks: %w", err)
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Claims{}, fmt.Errorf("cloudidentity: parse token: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return Claims{}, errors.New("cloudidentity: token must carry exactly one signature")
	}
	kid := jws.Signatures[0].Header.KeyID
	keys := set.Key(kid)
	if kid == "" || len(keys) == 0 {
		return Claims{}, errors.New("cloudidentity: token key is not in the JWKS")
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		return Claims{}, fmt.Errorf("cloudidentity: signature: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("cloudidentity: claims: %w", err)
	}
	t := now.Unix()
	if t < c.NotBefore || t >= c.Expiry {
		return Claims{}, errors.New("cloudidentity: token is outside its validity window")
	}
	return c, nil
}
