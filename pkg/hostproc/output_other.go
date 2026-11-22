//go:build !linux

package hostproc

import (
	"errors"
	"os"
)

// errNoJournalStream: there is no journald off Linux.
var errNoJournalStream = errors.New("no journal stream here")

// openJournalStream: there is no journald off Linux.
func openJournalStream(string) (*os.File, error) { return nil, errNoJournalStream }
