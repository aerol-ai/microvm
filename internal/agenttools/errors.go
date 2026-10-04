package agenttools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// Error codes. They are a stable contract: the CLI prints them in its --json
// error envelope and the MCP server puts them in tool errors, so agents and
// scripts branch on them. Add codes; never repurpose one.
const (
	CodeInvalidArgument    = "invalid_argument"
	CodeUnauthorized       = "unauthorized"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeConflict           = "conflict"
	CodeGone               = "gone"
	CodeTooLarge           = "too_large"
	CodeUnavailable        = "unavailable"
	CodeInternal           = "internal"
	CodeUnreachable        = "unreachable"
	CodeTimeout            = "timeout"
	CodeCanceled           = "canceled"
	CodeServerUnsupported  = "server_unsupported"
	CodeUnsupportedRuntime = "unsupported_runtime"
	CodeOutputTooLarge     = "output_too_large"
	CodeBinaryFile         = "binary_file"
	CodeEditConflict       = "edit_conflict"
	CodeCreateLimit        = "create_limit"
)

// Error is the machine-readable failure every agenttools operation returns.
// Message is for a person or a model; Hint, when set, names the next step
// (MCP tool errors carry it so the model can recover without guessing).
type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Retryable  bool   `json:"retryable"`
	Hint       string `json:"hint,omitempty"`
	cause      error
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.cause }

func newError(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithHint returns err classified, with hint attached when it has none yet.
func WithHint(err error, hint string) *Error {
	e := Classify(err)
	if e == nil {
		return nil
	}
	if e.Hint == "" {
		cp := *e
		cp.Hint = hint
		return &cp
	}
	return e
}

// Classify maps any error from the SDK, the network or agenttools onto an
// *Error. The code comes from the server's machine-readable code when it sent
// one, otherwise from the HTTP status, so the CLI and MCP report identical
// codes for identical failures.
func Classify(err error) *Error {
	if err == nil {
		return nil
	}
	var own *Error
	if errors.As(err, &own) {
		return own
	}
	if errors.Is(err, microvm.ErrNameLookupUnsupported) {
		return &Error{Code: CodeServerUnsupported, Message: err.Error(), cause: err}
	}
	var apiErr *microvm.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.Code
		if code == "" {
			code = codeForStatus(apiErr.StatusCode)
		}
		return &Error{
			Code:       code,
			Message:    apiErr.Message,
			HTTPStatus: apiErr.StatusCode,
			Retryable:  apiErr.Retryable(),
			cause:      err,
		}
	}
	// A by-name lookup that found nothing is not an HTTP error (the list
	// came back empty), but it means the same thing as a 404.
	if errors.Is(err, microvm.ErrNotFound) {
		return &Error{Code: CodeNotFound, Message: err.Error(), HTTPStatus: http.StatusNotFound, cause: err}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: CodeTimeout, Message: "timed out", cause: err}
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Code: CodeCanceled, Message: "canceled", cause: err}
	}
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) {
		return &Error{Code: CodeUnreachable, Message: err.Error(), Retryable: true, cause: err}
	}
	return &Error{Code: CodeInternal, Message: err.Error(), cause: err}
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusPreconditionFailed:
		return CodeInvalidArgument
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusGone:
		return CodeGone
	case http.StatusRequestEntityTooLarge:
		return CodeTooLarge
	case http.StatusMisdirectedRequest, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return CodeUnavailable
	case http.StatusNotImplemented:
		return CodeUnsupportedRuntime
	}
	if status >= 500 {
		return CodeInternal
	}
	return CodeInvalidArgument
}

// IsCode reports whether err classifies to code.
func IsCode(err error, code string) bool {
	e := Classify(err)
	return e != nil && e.Code == code
}
