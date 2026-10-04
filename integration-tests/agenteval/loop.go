// Package agenteval checks that a model can actually use the aerolvm MCP
// tools (plans/mcp-server-and-agent-cli.md §8, eng review D13). Claude gets
// the tools exactly as `aerolvm mcp` lists them and works through a task; the
// harness then checks the sandbox, not just the answer.
//
// The live tasks are in agenteval_test.go behind -tags=agenteval. An operator
// runs them against a local single-node sandboxd before changing a tool name,
// description or notice text, and before a release. They are never part of
// `make test` or CI: they call the Anthropic API. This file is the agent loop
// they share, kept free of the tag so loop_test.go checks it offline.
package agenteval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultModel is the model the eval runs against unless AEROLVM_EVAL_MODEL
// says otherwise.
const DefaultModel = "claude-opus-5-5"

const messagesURL = "https://api.anthropic.com/v1/messages"

// Anthropic is a minimal Messages API client: the eval needs one endpoint,
// and a raw request keeps the SDK out of go.mod.
type Anthropic struct {
	APIKey     string
	Model      string
	URL        string // defaults to the public Messages API
	HTTPClient *http.Client
	MaxTokens  int
	// Backoff is the first retry delay after a 429 or 5xx; it doubles.
	Backoff time.Duration
}

type block struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type message struct {
	Role    string  `json:"role"`
	Content []block `json:"content"`
}

type toolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type request struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Tools     []toolDef `json:"tools,omitempty"`
	Messages  []message `json:"messages"`
}

type response struct {
	Content    []block `json:"content"`
	StopReason string  `json:"stop_reason"`
}

const maxAttempts = 4

func (a *Anthropic) send(ctx context.Context, req request) (*response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := a.URL
	if url == "" {
		url = messagesURL
	}
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	backoff := a.Backoff
	if backoff == 0 {
		backoff = 2 * time.Second
	}
	for attempt := 1; ; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("content-type", "application/json")
		httpReq.Header.Set("x-api-key", a.APIKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
		resp, err := client.Do(httpReq)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		if retryable && attempt < maxAttempts {
			wait := backoff
			if s, err := strconv.Atoi(resp.Header.Get("retry-after")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			backoff *= 2
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("messages API: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
		}
		var out response
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("messages API reply: %w", err)
		}
		return &out, nil
	}
}

// Step is one tool call the model made and what it got back.
type Step struct {
	Tool       string
	Args       map[string]any
	IsError    bool
	Text       string         // the result as the model saw it
	Structured map[string]any // the tool's structured output, for checks
}

// Conversation is one agent session: a model, the MCP tools, and the
// message history across Ask calls.
type Conversation struct {
	model    *Anthropic
	session  *mcp.ClientSession
	system   string
	tools    []toolDef
	messages []message
	// MaxTurns bounds the model calls per Ask, so a model that loops on a
	// failing tool ends the task instead of spending without limit.
	MaxTurns int
	// Steps is every tool call, across all Ask calls, in order.
	Steps []Step
}

// NewConversation lists the session's tools and hands them to the model as
// they are: same names, descriptions and schemas a real MCP client sends.
func NewConversation(ctx context.Context, model *Anthropic, session *mcp.ClientSession, system string) (*Conversation, error) {
	c := &Conversation{model: model, session: session, system: system, MaxTurns: 20}
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		schema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return nil, err
		}
		c.tools = append(c.tools, toolDef{Name: tool.Name, Description: tool.Description, InputSchema: schema})
	}
	if len(c.tools) == 0 {
		return nil, fmt.Errorf("the MCP server lists no tools")
	}
	return c, nil
}

// Ask sends prompt as the user and runs the model's tool calls until it
// answers without one. It returns that answer.
func (c *Conversation) Ask(ctx context.Context, prompt string) (string, error) {
	c.messages = append(c.messages, message{Role: "user", Content: []block{{Type: "text", Text: prompt}}})
	maxTokens := c.model.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}
	for turn := 0; turn < c.MaxTurns; turn++ {
		resp, err := c.model.send(ctx, request{
			Model: c.model.Model, MaxTokens: maxTokens, System: c.system, Tools: c.tools, Messages: c.messages,
		})
		if err != nil {
			return "", err
		}
		c.messages = append(c.messages, message{Role: "assistant", Content: resp.Content})
		var results []block
		var text []string
		for _, b := range resp.Content {
			switch b.Type {
			case "text":
				text = append(text, b.Text)
			case "tool_use":
				results = append(results, c.callTool(ctx, b))
			}
		}
		if len(results) == 0 {
			return strings.Join(text, "\n"), nil
		}
		c.messages = append(c.messages, message{Role: "user", Content: results})
	}
	return "", fmt.Errorf("no final answer after %d model turns", c.MaxTurns)
}

func (c *Conversation) callTool(ctx context.Context, use block) block {
	step := Step{Tool: use.Name}
	_ = json.Unmarshal(use.Input, &step.Args)
	result := block{Type: "tool_result", ToolUseID: use.ID}
	res, err := c.session.CallTool(ctx, &mcp.CallToolParams{Name: use.Name, Arguments: step.Args})
	switch {
	case err != nil:
		step.IsError, step.Text = true, err.Error()
	default:
		step.IsError = res.IsError
		var parts []string
		for _, content := range res.Content {
			if t, ok := content.(*mcp.TextContent); ok {
				parts = append(parts, t.Text)
			}
		}
		step.Text = strings.Join(parts, "\n")
		if raw, err := json.Marshal(res.StructuredContent); err == nil {
			_ = json.Unmarshal(raw, &step.Structured)
		}
		if step.Text == "" && step.Structured != nil {
			raw, _ := json.Marshal(step.Structured)
			step.Text = string(raw)
		}
	}
	c.Steps = append(c.Steps, step)
	result.IsError = step.IsError
	result.Content = step.Text
	if result.Content == "" {
		result.Content = "(no output)"
	}
	return result
}

// Called reports whether the model called tool at least once.
func (c *Conversation) Called(tool string) bool {
	for _, s := range c.Steps {
		if s.Tool == tool {
			return true
		}
	}
	return false
}

// Summary is a one-line-per-call log of the session, for the test output.
func (c *Conversation) Summary() string {
	var b strings.Builder
	for i, s := range c.Steps {
		args, _ := json.Marshal(s.Args)
		mark := "ok"
		if s.IsError {
			mark = "error"
		}
		fmt.Fprintf(&b, "%2d. %s %s -> %s\n", i+1, s.Tool, truncate(string(args), 160), mark)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
