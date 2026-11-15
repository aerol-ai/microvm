package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// FeatureCodeInterpreter is the feature an agent lists on /version when it
// serves the code interpreter. Old Firecracker templates keep the agent they
// were built with, so every interpreter call checks it first.
const FeatureCodeInterpreter = "code.interpreter"

// CloseCodeRunTimeout is the close code the agent ends a run with when the
// run's timeout fired.
const CloseCodeRunTimeout = 4008

// codeRunInterruptGrace is how long a cancelled RunCode waits for the agent
// to confirm the interrupt before it drops the socket. It is longer than the
// agent's own interrupt-to-kill grace (2 s), so code that ignores SIGINT is
// still reported as interrupted. A variable for tests.
var codeRunInterruptGrace = 5 * time.Second

type CodeContext = sdktypes.CodeContext
type CodeContextOptions = sdktypes.CodeContextOptions
type RunCodeOptions = sdktypes.RunCodeOptions
type CodeResult = sdktypes.CodeResult
type ExecutionError = sdktypes.ExecutionError
type ExecutionLogs = sdktypes.ExecutionLogs
type Execution = sdktypes.Execution

// ErrCodeRunTimeout matches a *CodeRunError whose run timed out.
var ErrCodeRunTimeout = errors.New("code run timed out")

// CodeRunError is a run that did not end normally: the agent closed the
// stream with an error code, the run timed out (CloseCode 4008), or the
// connection dropped (1006). Execution holds what the run produced before
// that. errors.Is(err, ErrCodeRunTimeout) is true for a timeout.
type CodeRunError struct {
	CloseCode int
	Reason    string
	Execution *Execution
}

func (e *CodeRunError) Error() string {
	msg := fmt.Sprintf("code run failed (close %d)", e.CloseCode)
	if e.Timeout() {
		msg = "code run timed out"
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// Timeout reports whether the run's timeout ended it.
func (e *CodeRunError) Timeout() bool { return e.CloseCode == CloseCodeRunTimeout }

func (e *CodeRunError) Is(target error) bool { return target == ErrCodeRunTimeout && e.Timeout() }

func (c *Client) interpreterPath(id string) string {
	return c.versionPrefix + "/sandboxes/" + url.PathEscape(id) + "/toolbox/process/interpreter"
}

func (c *Client) codeContextPath(id, contextID string) (string, error) {
	if strings.TrimSpace(contextID) == "" {
		return "", errors.New("context id is required")
	}
	return c.interpreterPath(id) + "/context/" + url.PathEscape(contextID), nil
}

// CreateCodeContext starts a new interpreter context. Each call makes a new
// context, so it is sent once and not retried after it may have arrived.
func (c *Client) CreateCodeContext(ctx context.Context, id string, options CodeContextOptions) (CodeContext, error) {
	var response CodeContext
	if err := c.RequireToolboxFeatures(ctx, id, FeatureCodeInterpreter); err != nil {
		return response, err
	}
	_, err := c.doJSONHeaders(ctx, http.MethodPost, c.interpreterPath(id)+"/context", options, &response, retryUnsentOnly)
	return response, err
}

// ListCodeContexts lists the sandbox's contexts. The default python context
// is not listed.
func (c *Client) ListCodeContexts(ctx context.Context, id string) ([]CodeContext, error) {
	if err := c.RequireToolboxFeatures(ctx, id, FeatureCodeInterpreter); err != nil {
		return nil, err
	}
	var response struct {
		Contexts []CodeContext `json:"contexts"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.interpreterPath(id)+"/context", nil, &response); err != nil {
		return nil, err
	}
	if response.Contexts == nil {
		return []CodeContext{}, nil
	}
	return response.Contexts, nil
}

// GetCodeContext reads one context; an unknown id is ErrNotFound.
func (c *Client) GetCodeContext(ctx context.Context, id, contextID string) (CodeContext, error) {
	var response CodeContext
	path, err := c.codeContextPath(id, contextID)
	if err != nil {
		return response, err
	}
	if err := c.RequireToolboxFeatures(ctx, id, FeatureCodeInterpreter); err != nil {
		return response, err
	}
	err = c.doJSON(ctx, http.MethodGet, path, nil, &response)
	return response, err
}

// DeleteCodeContext stops a context's process and forgets it. An unknown id
// is ErrNotFound.
func (c *Client) DeleteCodeContext(ctx context.Context, id, contextID string) error {
	path, err := c.codeContextPath(id, contextID)
	if err != nil {
		return err
	}
	if err := c.RequireToolboxFeatures(ctx, id, FeatureCodeInterpreter); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil)
}

// RestartCodeContext starts the context's process again: same id, all
// variables gone. Not retried after it may have arrived, so a run that
// started in between does not lose its state to a second restart.
func (c *Client) RestartCodeContext(ctx context.Context, id, contextID string) (CodeContext, error) {
	var response CodeContext
	path, err := c.codeContextPath(id, contextID)
	if err != nil {
		return response, err
	}
	if err := c.RequireToolboxFeatures(ctx, id, FeatureCodeInterpreter); err != nil {
		return response, err
	}
	_, err = c.doJSONHeaders(ctx, http.MethodPost, path+"/restart", nil, &response, retryUnsentOnly)
	return response, err
}

type codeRunStart struct {
	Code      string            `json:"code"`
	ContextID string            `json:"contextId,omitempty"`
	Language  string            `json:"language,omitempty"`
	Envs      map[string]string `json:"envs,omitempty"`
	// A pointer, so 0 (no timeout) is sent and nil (agent default) is not.
	Timeout    *int `json:"timeout,omitempty"`
	RichOutput bool `json:"richOutput"`
}

// codeRunFrame is every field a server frame may carry. json, data and extra
// stay raw so a value of an unexpected shape drops only that field, not the
// whole result.
type codeRunFrame struct {
	Type         string          `json:"type"`
	Text         string          `json:"text"`
	Name         string          `json:"name"`
	Value        string          `json:"value"`
	Traceback    string          `json:"traceback"`
	Count        *int            `json:"count"`
	HTML         string          `json:"html"`
	Markdown     string          `json:"markdown"`
	SVG          string          `json:"svg"`
	PNG          string          `json:"png"`
	JPEG         string          `json:"jpeg"`
	PDF          string          `json:"pdf"`
	LaTeX        string          `json:"latex"`
	JSON         json.RawMessage `json:"json"`
	JavaScript   string          `json:"javascript"`
	Data         json.RawMessage `json:"data"`
	Extra        json.RawMessage `json:"extra"`
	IsMainResult bool            `json:"is_main_result"`
}

func rawObject(raw json.RawMessage) map[string]any {
	var out map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func (f codeRunFrame) result() CodeResult {
	return CodeResult{
		Text: f.Text, HTML: f.HTML, Markdown: f.Markdown, SVG: f.SVG,
		PNG: f.PNG, JPEG: f.JPEG, PDF: f.PDF, LaTeX: f.LaTeX,
		JSON: rawObject(f.JSON), JavaScript: f.JavaScript,
		Data: rawObject(f.Data), Extra: rawObject(f.Extra),
		IsMainResult: f.IsMainResult,
	}
}

// RunCode runs code in an interpreter context and returns what it produced
// once the run ends. The code's own exception is Execution.Error, with a nil
// error. A run that timed out or was cut off returns the partial Execution
// together with a *CodeRunError.
//
// Cancelling ctx interrupts the run: the agent stops it and RunCode returns
// the Execution with Interrupted set and a nil error. If the agent does not
// confirm within a few seconds, RunCode drops the socket and returns the
// partial Execution with ctx.Err(). Dropping the socket alone would not stop
// the run; the interrupt does.
//
// A run is sent once and never retried.
func (c *Client) RunCode(ctx context.Context, id, code string, options RunCodeOptions) (*Execution, error) {
	if options.ContextID != "" && options.Language != "" {
		return nil, errors.New("set context or language, not both")
	}
	if err := c.RequireToolboxFeatures(ctx, id, FeatureCodeInterpreter); err != nil {
		return nil, err
	}

	header := http.Header{}
	c.setAuthHeaders(header)
	conn, resp, wsURL, err := c.dialSandbox(ctx, c.interpreterPath(id)+"/execute", header)
	if err != nil {
		return nil, decorateHandshakeError("code run", wsURL, resp, err)
	}
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	start := codeRunStart{
		Code:       code,
		ContextID:  options.ContextID,
		Language:   options.Language,
		Envs:       options.Envs,
		Timeout:    options.TimeoutSeconds,
		RichOutput: true,
	}
	if err := conn.WriteJSON(start); err != nil {
		return nil, err
	}

	exec := &Execution{Results: []CodeResult{}, Logs: ExecutionLogs{Stdout: []string{}, Stderr: []string{}}}
	// Only the reader touches exec until it has returned, so the caller
	// never sees a half-applied frame.
	finished := make(chan error, 1)
	go func() { finished <- readCodeRun(conn, exec, options) }()

	select {
	case err := <-finished:
		return exec, err
	case <-ctx.Done():
	}

	// A client disconnect does not stop a run on the agent; the interrupt
	// does. The write deadline keeps a stuck socket from outliving the grace.
	_ = conn.SetWriteDeadline(time.Now().Add(codeRunInterruptGrace))
	_ = conn.WriteJSON(map[string]string{"type": "interrupt"})
	grace := time.NewTimer(codeRunInterruptGrace)
	defer grace.Stop()
	select {
	case err := <-finished:
		return exec, err
	case <-grace.C:
		_ = conn.Close()
		<-finished
		return exec, ctx.Err()
	}
}

// readCodeRun applies frames to exec until the agent closes the stream, and
// returns how the run ended. The close frame decides: a control frame says
// how the code finished, the close code whether the run itself did.
func readCodeRun(conn *websocket.Conn, exec *Execution, options RunCodeOptions) error {
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return codeRunCloseError(err, exec)
		}
		if messageType != websocket.TextMessage {
			continue
		}
		var frame codeRunFrame
		if json.Unmarshal(payload, &frame) != nil {
			continue
		}
		switch frame.Type {
		case "stdout":
			exec.Logs.Stdout = append(exec.Logs.Stdout, frame.Text)
			if options.OnStdout != nil {
				options.OnStdout(frame.Text)
			}
		case "stderr":
			exec.Logs.Stderr = append(exec.Logs.Stderr, frame.Text)
			if options.OnStderr != nil {
				options.OnStderr(frame.Text)
			}
		case "result":
			result := frame.result()
			exec.Results = append(exec.Results, result)
			if options.OnResult != nil {
				options.OnResult(result)
			}
		case "execution_count":
			if frame.Count != nil {
				count := *frame.Count
				exec.ExecutionCount = &count
			}
		case "error":
			codeErr := ExecutionError{Name: frame.Name, Value: frame.Value, Traceback: frame.Traceback}
			exec.Error = &codeErr
			if options.OnError != nil {
				options.OnError(codeErr)
			}
		case "control":
			if frame.Text == "interrupted" {
				exec.Interrupted = true
			}
		}
	}
}

func codeRunCloseError(err error, exec *Execution) error {
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		switch closeErr.Code {
		case websocket.CloseNormalClosure, websocket.CloseNoStatusReceived:
			return nil
		}
		return &CodeRunError{CloseCode: closeErr.Code, Reason: closeErr.Text, Execution: exec}
	}
	return &CodeRunError{CloseCode: websocket.CloseAbnormalClosure, Reason: err.Error(), Execution: exec}
}
