//go:build !linux

package sessions

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// Outside Linux there is no /proc to find a terminal's holders in; sessions
// run inside Linux sandboxes, so these only keep the package building for
// development on other systems.
func ptsPath(*os.File) string { return "" }

// StartPTY is pty.StartWithSize here; see the Linux version for why Linux
// swaps the master for a pollable duplicate.
func StartPTY(cmd *exec.Cmd, cols, rows uint16) (*os.File, error) {
	return pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
}

// SetWinsize is pty.Setsize here.
func SetWinsize(master *os.File, cols, rows uint16) error {
	return pty.Setsize(master, &pty.Winsize{Cols: cols, Rows: rows})
}

func killTerminalHolders(string) int { return 0 }
