package wasm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	daytonasdk "github.com/daytonaio/daytona/libs/sdk-go/pkg/daytona"
	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	toolbox "github.com/daytonaio/daytona/libs/toolbox-api-client-go"
)

// daytonaProcess is the Daytona Go SDK pinned in go.mod, pointed at the
// WASM toolbox of the stdio-guest sandbox the way the Daytona facade
// proxies it: the toolbox URL is the proxy URL plus the sandbox id. The
// SDK's toolbox client decodes every response strictly (required fields),
// so these calls also prove the wire shapes.
func daytonaProcess(t *testing.T, d *Driver, id string) *daytonasdk.ProcessService {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.ServeToolbox(r.Context(), id, "tok", w, r)
	}))
	t.Cleanup(ts.Close)
	cfg := toolbox.NewConfiguration()
	cfg.Servers = toolbox.ServerConfigurations{{URL: ts.URL + "/" + id}}
	cfg.HTTPClient = ts.Client()
	cfg.AddDefaultHeader("Authorization", "Bearer tok")
	return daytonasdk.NewProcessService(toolbox.NewAPIClient(cfg), nil, daytonatypes.CodeLanguagePython)
}

func sdkCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// The Daytona Go SDK's session calls work on a WASM sandbox: create, a
// sync and an async command, the command's status and logs (read and
// followed), list, and delete.
func TestDaytonaGoSDKSessionsOnWasm(t *testing.T) {
	d, id := streamDriver(t, Config{}, models.CreateSandboxRequest{})
	proc := daytonaProcess(t, d, id)
	ctx := sdkCtx(t)

	if err := proc.CreateSession(ctx, "sdk"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	res, err := proc.ExecuteSessionCommand(ctx, "sdk", `aerolstdio args "hello world"`, false, false)
	if err != nil {
		t.Fatalf("sync ExecuteSessionCommand: %v", err)
	}
	if res["exitCode"] != int32(0) || res["stdout"] != "hello world\n" || res["id"] == "" {
		t.Fatalf("sync result = %v", res)
	}

	async, err := proc.ExecuteSessionCommand(ctx, "sdk", "aerolstdio stderr oops", true, false)
	if err != nil {
		t.Fatalf("async ExecuteSessionCommand: %v", err)
	}
	cmdID, _ := async["id"].(string)
	if cmdID == "" || async["exitCode"] != nil {
		t.Fatalf("async result = %v", async)
	}
	waitFor(t, "async command to end", func() bool {
		status, err := proc.GetSessionCommand(ctx, "sdk", cmdID)
		return err == nil && status["exitCode"] == int32(0)
	})
	logs, err := proc.GetSessionCommandLogs(ctx, "sdk", cmdID)
	if err != nil || logs.GetStderr() != "oops" || logs.GetStdout() != "" || logs.GetOutput() != "oops" {
		t.Fatalf("GetSessionCommandLogs = %+v, %v", logs, err)
	}

	// Following a command that has ended replays it and ends cleanly: the
	// SDK reports no error for a normal close.
	stdout, stderr := make(chan string, 8), make(chan string, 8)
	if err := proc.GetSessionCommandLogsStream(ctx, "sdk", cmdID, stdout, stderr); err != nil {
		t.Fatalf("GetSessionCommandLogsStream: %v", err)
	}
	var gotErr string
	for chunk := range stderr {
		gotErr += chunk
	}
	if gotErr != "oops" {
		t.Fatalf("followed stderr = %q", gotErr)
	}

	session, err := proc.GetSession(ctx, "sdk")
	if err != nil || session["sessionId"] != "sdk" {
		t.Fatalf("GetSession = %v, %v", session, err)
	}
	if cmds, _ := session["commands"].([]toolbox.Command); len(cmds) != 2 || cmds[1].GetId() != cmdID || cmds[1].GetExitCode() != 0 {
		t.Fatalf("session commands = %+v", session["commands"])
	}
	sessions, err := proc.ListSessions(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListSessions = %v, %v", sessions, err)
	}
	if err := proc.DeleteSession(ctx, "sdk"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := proc.GetSession(ctx, "sdk"); err == nil {
		t.Fatal("GetSession after delete succeeded")
	}
}
