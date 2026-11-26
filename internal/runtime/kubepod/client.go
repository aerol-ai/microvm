package kubepod

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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Client is the few pod calls the driver makes, over plain HTTPS: create,
// get, delete and list. sandboxd carries no Kubernetes client library (the
// agent-sandbox API in internal/kubeapi calls the API server the same
// way), so neither it nor its dependencies are in the binary.
type Client struct {
	host  string
	token func() (string, error)
	http  *http.Client
}

// NewClient is a Client for the API server at host (https://name:port).
// token, when set, is asked for a bearer token on every call. hc carries
// the TLS settings; nil uses http.DefaultClient's.
func NewClient(host string, token func() (string, error), hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{}
	}
	if hc.Timeout == 0 {
		hc.Timeout = callTimeout
	}
	return &Client{host: strings.TrimRight(host, "/"), token: token, http: hc}
}

// callTimeout bounds one call. No call the driver makes streams.
const callTimeout = 30 * time.Second

// maxResponseBytes bounds a reply the client reads. A page of the largest
// list it asks for (listPageSize pods of a few KB each) fits well inside.
const maxResponseBytes = 16 << 20

// serviceAccountDir holds the pod's service account files (the same paths
// as client-go's rest.InClusterConfig). A variable so tests can point it at
// a folder of their own.
var serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// InClusterClient is a Client for the pod's own service account. The token
// is read again for every call: the kubelet rotates it.
func InClusterClient() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kubepod: not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST unset)")
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("kubepod: service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kubepod: service account CA has no certificate")
	}
	token := func() (string, error) {
		b, err := os.ReadFile(serviceAccountDir + "/token")
		return strings.TrimSpace(string(b)), err
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}}
	return NewClient("https://"+net.JoinHostPort(host, port), token, hc), nil
}

// APIError is a call the API server answered with an error status.
type APIError struct {
	Method  string
	Path    string
	Code    int
	Reason  string // metav1.Status reason, such as NotFound or AlreadyExists
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kubepod: %s %s: %d %s: %s", e.Method, e.Path, e.Code, e.Reason, e.Message)
}

func apiCode(err error) (int, string) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code, ae.Reason
	}
	return 0, ""
}

func isNotFound(err error) bool {
	code, _ := apiCode(err)
	return code == http.StatusNotFound
}

func isAlreadyExists(err error) bool {
	code, reason := apiCode(err)
	return code == http.StatusConflict && reason == "AlreadyExists"
}

// isConflict is a failed precondition: the pod a delete named by UID was
// replaced by another of the same name.
func isConflict(err error) bool {
	code, reason := apiCode(err)
	return code == http.StatusConflict && reason == "Conflict"
}

func podsPath(namespace string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods"
}

func podPath(namespace, name string) string {
	return podsPath(namespace) + "/" + url.PathEscape(name)
}

// CreatePod creates p in namespace and returns the pod the server stored.
func (c *Client) CreatePod(ctx context.Context, namespace string, p *Pod) (*Pod, error) {
	var out Pod
	if err := c.do(ctx, http.MethodPost, podsPath(namespace), p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPod reads one pod. A missing pod is an *APIError with Code 404.
func (c *Client) GetPod(ctx context.Context, namespace, name string) (*Pod, error) {
	var out Pod
	if err := c.do(ctx, http.MethodGet, podPath(namespace, name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeletePod asks for a pod to be deleted after grace. uid, when set, is a
// precondition: the server refuses (409 Conflict) when the pod of that name
// is no longer the one the caller saw. grace is never zero: a zero grace
// removes the object before the kubelet has stopped anything, and the
// name is what keeps two copies of a sandbox apart.
func (c *Client) DeletePod(ctx context.Context, namespace, name, uid string, grace time.Duration) error {
	secs := int64(grace / time.Second)
	if secs < 1 {
		secs = 1
	}
	opts := map[string]any{
		"apiVersion":         "v1",
		"kind":               "DeleteOptions",
		"gracePeriodSeconds": secs,
		"propagationPolicy":  "Background",
	}
	if uid != "" {
		opts["preconditions"] = map[string]string{"uid": uid}
	}
	return c.do(ctx, http.MethodDelete, podPath(namespace, name), opts, nil)
}

// listPageSize is the pods asked for per list call. A worker holds a few
// hundred sandboxes at most; pages keep each reply small either way.
const listPageSize = 250

// ListPods lists the pods in namespace that match selector, all pages.
func (c *Client) ListPods(ctx context.Context, namespace, selector string) ([]Pod, error) {
	var pods []Pod
	cont := ""
	for {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(listPageSize))
		if selector != "" {
			q.Set("labelSelector", selector)
		}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []Pod `json:"items"`
		}
		if err := c.do(ctx, http.MethodGet, podsPath(namespace)+"?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		pods = append(pods, page.Items...)
		if page.Metadata.Continue == "" {
			return pods, nil
		}
		cont = page.Metadata.Continue
	}
}

// CanList is one list call for a single pod: it proves the API server
// answers and that this service account may list pods there.
func (c *Client) CanList(ctx context.Context, namespace, selector string) error {
	q := url.Values{}
	q.Set("limit", "1")
	if selector != "" {
		q.Set("labelSelector", selector)
	}
	return c.do(ctx, http.MethodGet, podsPath(namespace)+"?"+q.Encode(), nil, &struct{}{})
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.host+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != nil {
		tok, err := c.token()
		if err != nil {
			return fmt.Errorf("kubepod: service account token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kubepod: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("kubepod: %s %s: read reply: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		ae := &APIError{Method: method, Path: path, Code: resp.StatusCode}
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &st) == nil {
			ae.Reason, ae.Message = st.Reason, st.Message
		}
		if ae.Message == "" {
			ae.Message = strings.TrimSpace(string(raw))
		}
		return ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("kubepod: %s %s: decode reply: %w", method, path, err)
	}
	return nil
}
