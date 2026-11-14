package e2b

import "net/http"

// EnvdCall is one envd request the E2B SDK makes through this facade's
// /envd/* pass-through (runtime_proxy.go).
type EnvdCall struct {
	Method string
	Path   string
}

// EnvdCalls lists the envd routes the E2B SDK calls: health, file read and
// write, and the process and filesystem Connect RPCs. The facade forwards the
// whole /envd prefix, so this list is what the toolboxd route inventory test
// (plan X2) checks toolboxd answers.
func EnvdCalls() []EnvdCall {
	calls := []EnvdCall{
		{Method: http.MethodGet, Path: "/envd/health"},
		{Method: http.MethodGet, Path: "/envd/files"},
		{Method: http.MethodPost, Path: "/envd/files"},
	}
	for _, rpc := range []string{"List", "Start", "Connect", "Update", "SendInput", "SendSignal", "CloseStdin", "StreamInput"} {
		calls = append(calls, EnvdCall{Method: http.MethodPost, Path: "/envd/process.Process/" + rpc})
	}
	for _, rpc := range []string{"Stat", "MakeDir", "Move", "ListDir", "Remove", "WatchDir", "CreateWatcher", "GetWatcherEvents", "RemoveWatcher"} {
		calls = append(calls, EnvdCall{Method: http.MethodPost, Path: "/envd/filesystem.Filesystem/" + rpc})
	}
	return calls
}
