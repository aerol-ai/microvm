package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The body E2B SDK 2.64 sends to POST /v2/sandboxes, with every field it
// can carry that this facade answers.
const v2CreateBody = `{"templateID":"base","timeout":120,"metadata":{"team":"v2"},"envVars":{"A":"1"},` +
	`"cpuCount":2,"allow_internet_access":true,"network":{"allowPublicTraffic":false,"httpsPorts":[443]},` +
	`"autoPause":true,"autoPauseMemory":false,"autoResume":{"enabled":false}}`

func TestV2CreateAndConnect(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	create := func() sandboxResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/e2b/v2/sandboxes", strings.NewReader(v2CreateBody))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("v2 create: %d %s", rec.Code, rec.Body.String())
		}
		var created sandboxResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		return created
	}
	created := create()
	if created.SandboxID == "" || created.ClientID == "" || created.EnvdVersion == "" || created.TemplateID != "base" ||
		created.EnvdAccessToken == "" || created.TrafficAccessToken == nil {
		t.Fatalf("v2 create = %+v; v2 has no secure field, so the sandbox must be secured", created)
	}
	// A retried create is the same sandbox, as on v1.
	if again := create(); again.SandboxID != created.SandboxID {
		t.Fatalf("retried v2 create made %s, want %s", again.SandboxID, created.SandboxID)
	}
	sb, err := st.Get(context.Background(), created.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Tags["team"] != "v2" {
		t.Fatalf("metadata lost: %+v", sb.Tags)
	}

	connect := func(id, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/e2b/v2/sandboxes/"+id+"/connect", strings.NewReader(body)))
		return rec
	}
	// E2B SDK 2.64 leaves timeout out unless the caller set one; E2B then
	// uses 300 s, past the create's 120 s.
	if rec := connect(created.SandboxID, `{}`); rec.Code != http.StatusOK {
		t.Fatalf("connect with no timeout: %d %s", rec.Code, rec.Body.String())
	}
	sb, _ = st.Get(context.Background(), created.SandboxID)
	if sb.Lifecycle.StopAtAge < 300*time.Second {
		t.Fatalf("a connect with no timeout did not extend the deadline: %+v", sb.Lifecycle)
	}
	cases := []struct {
		name, id, body string
		want           int
	}{
		{name: "no timeout", id: created.SandboxID, body: `{}`, want: http.StatusOK},
		{name: "timeout and memory", id: created.SandboxID, body: `{"timeout":600,"memory":false}`, want: http.StatusOK},
		{name: "zero timeout", id: created.SandboxID, body: `{"timeout":0}`, want: http.StatusBadRequest},
		{name: "bad JSON", id: created.SandboxID, body: `{"timeout":`, want: http.StatusBadRequest},
		{name: "unknown sandbox", id: "sb-missing", body: `{}`, want: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := connect(tc.id, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if tc.want != http.StatusOK {
				return
			}
			var got sandboxResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &got)
			if got.SandboxID != created.SandboxID || got.EnvdAccessToken != created.EnvdAccessToken || got.TrafficAccessToken == nil {
				t.Fatalf("connect = %s", rec.Body.String())
			}
		})
	}
}

func TestCreateIAM(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	cases := []struct {
		name, iam string
		want      int
	}{
		{name: "no tokens", iam: `{}`, want: http.StatusCreated},
		{name: "empty tokens", iam: `{"tokens":{}}`, want: http.StatusCreated},
		{name: "tokens", iam: `{"tokens":{"aws":{"audience":"sts.amazonaws.com","tokenType":"jwt"}}}`, want: http.StatusNotImplemented},
		{name: "not an object", iam: `"aws"`, want: http.StatusBadRequest},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"templateID":"base","metadata":{"case":"` + strconv.Itoa(i) + `"},"iam":` + tc.iam + `}`
			for _, path := range []string{"/e2b/sandboxes", "/e2b/v2/sandboxes"} {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
				if rec.Code != tc.want {
					t.Fatalf("%s: %d %s, want %d", path, rec.Code, rec.Body.String(), tc.want)
				}
				if tc.want == http.StatusNotImplemented && !strings.Contains(rec.Body.String(), "iam workload identity is not supported") {
					t.Fatalf("%s: body %s", path, rec.Body.String())
				}
			}
		})
	}
}
