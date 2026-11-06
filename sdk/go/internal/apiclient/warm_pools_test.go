package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWarmPoolCalls(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	pool := models.WarmPool{Image: "ghcr.io/acme/agent:1", Depth: 2, Generation: 1, CreatedAt: at, UpdatedAt: at,
		Status: &models.WarmPoolStatus{Ready: 1, Target: 2, Servers: []models.WarmPoolServerStatus{{NodeID: "n1", Ready: 1, Target: 2, Stale: true}}}}
	poolJSON, _ := json.Marshal(pool)
	tests := []struct {
		name, wantMethod, wantPath, wantBody string
		status                               int
		reply                                string
		call                                 func(*Client) (any, error)
		want                                 any
	}{
		{
			name: "put keeps the image's slashes and escapes each segment", wantMethod: http.MethodPut,
			wantPath: "/v1/warm-pools/ghcr.io/acme/agent:1", wantBody: `{"depth":2}`, status: http.StatusOK, reply: string(poolJSON),
			call: func(c *Client) (any, error) {
				return c.PutWarmPool(ctx, "ghcr.io/acme/agent:1", models.WarmPoolRequest{Depth: 2})
			},
			want: pool,
		},
		{
			name: "a demand-following entry sends its range", wantMethod: http.MethodPut,
			wantPath: "/v1/warm-pools/python:3.12", wantBody: `{"depth":0,"min_depth":1,"max_depth":4}`, status: http.StatusOK,
			reply: `{"image":"python:3.12","depth":0,"min_depth":1,"max_depth":4,"generation":1}`,
			call: func(c *Client) (any, error) {
				return c.PutWarmPool(ctx, "python:3.12", models.WarmPoolRequest{MinDepth: 1, MaxDepth: 4})
			},
			want: models.WarmPool{Image: "python:3.12", MinDepth: 1, MaxDepth: 4, Generation: 1},
		},
		{
			name: "a segment with a space is escaped", wantMethod: http.MethodGet,
			wantPath: "/v1/warm-pools/odd%20name/img:1", status: http.StatusOK, reply: string(poolJSON),
			call: func(c *Client) (any, error) { return c.GetWarmPool(ctx, "odd name/img:1") },
			want: pool,
		},
		{
			name: "list decodes every entry", wantMethod: http.MethodGet, wantPath: "/v1/warm-pools",
			status: http.StatusOK, reply: `{"pools":[` + string(poolJSON) + `]}`,
			call: func(c *Client) (any, error) { return c.ListWarmPools(ctx) },
			want: []models.WarmPool{pool},
		},
		{
			name: "a null list is empty, not nil", wantMethod: http.MethodGet, wantPath: "/v1/warm-pools",
			status: http.StatusOK, reply: `{"pools":null}`,
			call: func(c *Client) (any, error) { return c.ListWarmPools(ctx) },
			want: []models.WarmPool{},
		},
		{
			name: "delete", wantMethod: http.MethodDelete, wantPath: "/v1/warm-pools/python:3.12", status: http.StatusNoContent,
			call: func(c *Client) (any, error) { return nil, c.DeleteWarmPool(ctx, "python:3.12") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.wantMethod || r.URL.EscapedPath() != tt.wantPath {
					t.Errorf("request = %s %s, want %s %s", r.Method, r.URL.EscapedPath(), tt.wantMethod, tt.wantPath)
				}
				if tt.wantBody != "" {
					var got, want map[string]any
					_ = json.NewDecoder(r.Body).Decode(&got)
					_ = json.Unmarshal([]byte(tt.wantBody), &want)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("body = %v, want %v", got, want)
					}
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.reply))
			}))
			defer server.Close()
			client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
			got, err := tt.call(client)
			if err != nil {
				t.Fatalf("call error = %v", err)
			}
			if tt.want != nil && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestWarmPoolListError: a refused list surfaces the error, not an empty
// list a caller would read as "no entries".
func TestWarmPoolListError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"role runner cannot fleet.admin"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	if pools, err := client.ListWarmPools(context.Background()); err == nil || pools != nil {
		t.Fatalf("ListWarmPools = %v, %v; want an error", pools, err)
	}
}
