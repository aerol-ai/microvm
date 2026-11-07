//go:build !linux

package sessions

import "os"

// Outside Linux there is no /proc to find a terminal's holders in; sessions
// run inside Linux sandboxes, so these only keep the package building for
// development on other systems.
func ptsPath(*os.File) string { return "" }

func killTerminalHolders(string) int { return 0 }
