package codeinterp

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidEnv is returned for a run whose env cannot be set: adapters
// answer it as a bad request.
var ErrInvalidEnv = errors.New("invalid environment variable")

// ValidateEnv rejects env a process environment cannot hold. Every driver
// sets the run's env with its language's own call; a name with "=" became a
// different variable there (ZZA=B=C set ZZA to "B=C"), and a NUL made the
// python driver fail before its run started, which lost the context.
func ValidateEnv(env map[string]string) error {
	for name, value := range env {
		switch {
		case name == "":
			return fmt.Errorf("%w: empty name", ErrInvalidEnv)
		case strings.ContainsAny(name, "=\x00"):
			return fmt.Errorf("%w: name %q contains '=' or NUL", ErrInvalidEnv, name)
		case strings.ContainsRune(value, 0):
			return fmt.Errorf("%w: value of %q contains NUL", ErrInvalidEnv, name)
		}
	}
	return nil
}
