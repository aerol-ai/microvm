package daytona

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ER5 on the Daytona path: executeCommand (RoundTripToolbox) never sends a
// cap of its own, so the operator's default reaches toolboxd, and with a
// maximum set the uncapped command gets the maximum. The Daytona SDK has no
// cap option, so "a larger cap lowered" is this facade's no-cap case.
func TestDaytonaExecuteCommandGetsOperatorOutputLimits(t *testing.T) {
	for _, tc := range []struct {
		name             string
		def, max         int64
		wantOut, wantErr int64
	}{
		{name: "off", wantOut: 0, wantErr: 0},
		{name: "default filled in", def: 4096, max: 1 << 20, wantOut: 4096, wantErr: 4096},
		{name: "maximum applied to an uncapped command", max: 1 << 20, wantOut: 1 << 20, wantErr: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var got models.ExecRequest
			facadeURL, id := newToolboxExecEnvWithConfig(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				_ = json.NewDecoder(r.Body).Decode(&got)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"stdout":"ok","stderr":"","exit_code":0,"duration_ms":1}`)
			}, func(cfg *config.Config) {
				cfg.ExecOutputDefaultBytes = tc.def
				cfg.ExecOutputMaxBytes = tc.max
			})

			resp, err := http.Post(facadeURL+ToolboxPrefix+"/"+id+"/process/execute", "application/json", strings.NewReader(`{"command":"echo ok"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("executeCommand = %d %s", resp.StatusCode, body)
			}
			mu.Lock()
			defer mu.Unlock()
			if got.Command != "echo ok" || got.MaxStdoutBytes != tc.wantOut || got.MaxStderrBytes != tc.wantErr {
				t.Fatalf("toolboxd got %+v, want caps %d/%d", got, tc.wantOut, tc.wantErr)
			}
		})
	}
}
