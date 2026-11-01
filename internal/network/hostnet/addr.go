package hostnet

import (
	"errors"
	"strings"
)

// NetnsIPv4Addrs returns the IPv4 addresses on the non-loopback interfaces
// of the network namespace bind-mounted at path: the address a workload
// started in that namespace comes up at. A namespace with no such address
// returns an empty list, not an error.
//
// The containerd netns pool asks this of a warm slot that outlived a
// restart before it hands the slot out again, because a sandbox's rules
// go onto the slot's recorded address before its workload starts: a row
// whose namespace holds another address would put them on the wrong one.
func NetnsIPv4Addrs(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("read netns addresses: netns path is required")
	}
	return netnsIPv4Addrs(path)
}
