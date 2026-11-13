package kubeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Who may call (plan §15.3, §16). The kube-apiserver forwards an
// aggregated request with a client certificate from its front-proxy CA and
// the caller in X-Remote-* headers; this server trusts those headers only
// on a connection that presented such a certificate, then asks the
// kube-apiserver whether that caller may do this (SubjectAccessReview), so
// Kubernetes RBAC decides, as for any other resource.

// User is the Kubernetes caller of a request.
type User struct {
	Name   string
	Groups []string
	Extra  map[string][]string
}

// Attributes is what a request asks to do, in RBAC's terms.
type Attributes struct {
	Verb      string
	Group     string
	Resource  string
	Namespace string
	Name      string
}

// Authenticator says who sent a request.
type Authenticator interface {
	Authenticate(r *http.Request) (User, error)
}

// Authorizer says whether a user may do something.
type Authorizer interface {
	Authorize(ctx context.Context, u User, a Attributes) (allowed bool, reason string, err error)
}

// ErrUnauthenticated is a request without a front-proxy certificate the
// server trusts.
var ErrUnauthenticated = errors.New("kubeapi: the request did not come through the Kubernetes API server")

// FrontProxy authenticates the kube-apiserver's forwarded requests
// (requestheader authentication, the same contract metrics-server uses).
type FrontProxy struct {
	CAs          *x509.CertPool
	AllowedNames []string // empty: any certificate the CAs signed
	UserHeaders  []string
	GroupHeaders []string
	ExtraPrefix  []string
}

// Authenticate checks the client certificate and reads the caller.
func (f *FrontProxy) Authenticate(r *http.Request) (User, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || f.CAs == nil {
		return User{}, ErrUnauthenticated
	}
	leaf := r.TLS.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: f.CAs, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return User{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if len(f.AllowedNames) > 0 && !slices.Contains(f.AllowedNames, leaf.Subject.CommonName) {
		return User{}, fmt.Errorf("%w: certificate %q is not an allowed front proxy", ErrUnauthenticated, leaf.Subject.CommonName)
	}
	u := User{Extra: map[string][]string{}}
	for _, h := range orDefault(f.UserHeaders, "X-Remote-User") {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			u.Name = v
			break
		}
	}
	if u.Name == "" {
		return User{}, fmt.Errorf("%w: no user header", ErrUnauthenticated)
	}
	for _, h := range orDefault(f.GroupHeaders, "X-Remote-Group") {
		u.Groups = append(u.Groups, r.Header.Values(h)...)
	}
	for _, prefix := range orDefault(f.ExtraPrefix, "X-Remote-Extra-") {
		for k, vs := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), strings.ToLower(prefix)) {
				key := strings.ToLower(k[len(prefix):])
				u.Extra[key] = append(u.Extra[key], vs...)
			}
		}
	}
	return u, nil
}

func orDefault(v []string, d string) []string {
	if len(v) == 0 {
		return []string{d}
	}
	return v
}

// ServingTLS is the listener's TLS: the serving pair, and the front-proxy
// CAs a client certificate is checked against. A connection without a
// certificate is accepted at the TLS layer (health checks have none) and
// refused by Authenticate.
func ServingTLS(cert tls.Certificate, fp *FrontProxy) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    fp.CAs,
	}
}

// KubeClient is the few kube-apiserver calls the API makes, over plain
// HTTPS with the pod's service account: no client library.
type KubeClient struct {
	Host   string
	Token  func() (string, error)
	Client *http.Client
}

// In-cluster paths (k8s.io/client-go rest.InClusterConfig).
const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
)

// InClusterClient is a KubeClient for the pod's own service account. The
// token is read for each call: the kubelet rotates it.
func InClusterClient() (*KubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kubeapi: not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST unset)")
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("kubeapi: service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kubeapi: service account CA has no certificate")
	}
	return &KubeClient{
		Host: "https://" + net.JoinHostPort(host, port),
		Token: func() (string, error) {
			b, err := os.ReadFile(serviceAccountDir + "/token")
			return strings.TrimSpace(string(b)), err
		},
		Client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}},
	}, nil
}

func (k *KubeClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Host+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if k.Token != nil {
		tok, err := k.Token()
		if err != nil {
			return fmt.Errorf("kubeapi: service account token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("kubeapi: %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.Unmarshal(raw, out)
}

// FrontProxyConfig reads the front-proxy settings the kube-apiserver
// publishes (kube-system/extension-apiserver-authentication).
func (k *KubeClient) FrontProxyConfig(ctx context.Context) (*FrontProxy, error) {
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication", nil, &cm); err != nil {
		return nil, err
	}
	pem := cm.Data["requestheader-client-ca-file"]
	pool := x509.NewCertPool()
	if pem == "" || !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil, errors.New("kubeapi: the cluster publishes no front-proxy CA (requestheader-client-ca-file)")
	}
	list := func(key string) []string {
		var out []string
		_ = json.Unmarshal([]byte(cm.Data[key]), &out)
		return out
	}
	return &FrontProxy{
		CAs:          pool,
		AllowedNames: list("requestheader-allowed-names"),
		UserHeaders:  list("requestheader-username-headers"),
		GroupHeaders: list("requestheader-group-headers"),
		ExtraPrefix:  list("requestheader-extra-headers-prefix"),
	}, nil
}

// SubjectAccessReview asks the kube-apiserver whether u may do a.
func (k *KubeClient) SubjectAccessReview(ctx context.Context, u User, a Attributes) (bool, string, error) {
	type resourceAttributes struct {
		Namespace string `json:"namespace,omitempty"`
		Verb      string `json:"verb"`
		Group     string `json:"group"`
		Resource  string `json:"resource"`
		Name      string `json:"name,omitempty"`
	}
	in := map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SubjectAccessReview",
		"spec": map[string]any{
			"user": u.Name, "groups": u.Groups, "extra": u.Extra,
			"resourceAttributes": resourceAttributes{Namespace: a.Namespace, Verb: a.Verb, Group: a.Group, Resource: a.Resource, Name: a.Name},
		},
	}
	var out struct {
		Status struct {
			Allowed bool   `json:"allowed"`
			Denied  bool   `json:"denied"`
			Reason  string `json:"reason"`
		} `json:"status"`
	}
	if err := k.do(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/subjectaccessreviews", in, &out); err != nil {
		return false, "", err
	}
	return out.Status.Allowed && !out.Status.Denied, out.Status.Reason, nil
}

// CachedAuthorizer remembers answers for a short while: a watch reconnect
// or a paged list asks the same question many times.
type CachedAuthorizer struct {
	Next Authorizer
	TTL  time.Duration
	now  func() time.Time

	mu      sync.Mutex
	answers map[string]cachedAnswer
}

type cachedAnswer struct {
	allowed bool
	reason  string
	at      time.Time
}

// maxCachedAnswers bounds the cache; past it, it starts over.
const maxCachedAnswers = 10000

// Authorize answers from the cache or asks Next. Errors are not cached.
func (c *CachedAuthorizer) Authorize(ctx context.Context, u User, a Attributes) (bool, string, error) {
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	groups := slices.Clone(u.Groups)
	slices.Sort(groups)
	key := strings.Join([]string{u.Name, strings.Join(groups, ","), fmt.Sprint(u.Extra), a.Verb, a.Group, a.Resource, a.Namespace, a.Name}, "\x00")
	c.mu.Lock()
	if ans, ok := c.answers[key]; ok && now().Sub(ans.at) < c.TTL {
		c.mu.Unlock()
		return ans.allowed, ans.reason, nil
	}
	c.mu.Unlock()
	allowed, reason, err := c.Next.Authorize(ctx, u, a)
	if err != nil {
		return false, "", err
	}
	c.mu.Lock()
	if c.answers == nil || len(c.answers) >= maxCachedAnswers {
		c.answers = map[string]cachedAnswer{}
	}
	c.answers[key] = cachedAnswer{allowed: allowed, reason: reason, at: now()}
	c.mu.Unlock()
	return allowed, reason, nil
}

// AuthorizerFunc adapts a function, such as KubeClient.SubjectAccessReview.
type AuthorizerFunc func(ctx context.Context, u User, a Attributes) (bool, string, error)

func (f AuthorizerFunc) Authorize(ctx context.Context, u User, a Attributes) (bool, string, error) {
	return f(ctx, u, a)
}
