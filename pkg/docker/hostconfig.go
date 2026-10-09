package docker

// sandboxCapDrop is removed from every non-privileged sandbox container.
// NET_RAW lets a sandbox send packets with a neighbour's source IP, which
// defeats per-IP egress rules and the egress gateway's source-IP identity
// (plans/egress-domain-filtering.md P0-2, CEO D8). ping stops working inside
// sandboxes; that is the accepted cost.
var sandboxCapDrop = []string{"NET_RAW"}

// sandboxHostConfig is the HostConfig base shared by cold creates and warm
// parks, so both paths drop the same capabilities. A privileged sandbox gets
// every capability by design, so no drop is sent for it; gateway mode refuses
// privileged nodes instead (plan §5.3, CEO D18).
func sandboxHostConfig(privileged bool, binds []string) map[string]any {
	hostConfig := map[string]any{
		"Privileged": privileged,
		"Binds":      binds,
	}
	if !privileged {
		hostConfig["CapDrop"] = append([]string(nil), sandboxCapDrop...)
	}
	return hostConfig
}
