package runloop

import "net/http"

// ToolboxCall is one toolboxd request this facade makes, with sample ids in
// place of real session and command ids.
type ToolboxCall struct {
	Method string
	Path   string
}

// ToolboxCalls lists every toolboxd request the Runloop facade makes. The
// toolboxd route inventory test (plan X2) checks toolboxd answers each one,
// and TestToolboxCallsCoverEveryCallSite keeps this list in step with the
// call sites in this package.
func ToolboxCalls() []ToolboxCall {
	return []ToolboxCall{
		{Method: http.MethodPost, Path: "/process/execute"},
		{Method: http.MethodPost, Path: "/process/session"},
		{Method: http.MethodGet, Path: "/process/session/s1"},
		{Method: http.MethodDelete, Path: "/process/session/s1"},
		{Method: http.MethodPost, Path: "/process/session/s1/exec"},
		{Method: http.MethodGet, Path: "/process/session/s1/command/c1"},
		{Method: http.MethodGet, Path: "/process/session/s1/command/c1/logs"},
		{Method: http.MethodPost, Path: "/process/session/s1/command/c1/input"},
		{Method: http.MethodGet, Path: "/files/download"},
		{Method: http.MethodPost, Path: "/files/upload"},
	}
}
