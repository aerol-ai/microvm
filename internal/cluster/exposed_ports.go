package cluster

// exposedPortRoutesForPlacement returns the new route-metadata map when
// present and falls back to the legacy port->protocol map for older snapshots.
func exposedPortRoutesForPlacement(p Placement) map[int]ExposedPortRoute {
	if len(p.ExposedPortRoutes) > 0 {
		out := make(map[int]ExposedPortRoute, len(p.ExposedPortRoutes))
		for port, route := range p.ExposedPortRoutes {
			out[port] = route
		}
		return out
	}
	if len(p.ExposedPorts) == 0 {
		return nil
	}
	out := make(map[int]ExposedPortRoute, len(p.ExposedPorts))
	for port, protocol := range p.ExposedPorts {
		out[port] = ExposedPortRoute{Protocol: protocol}
	}
	return out
}

func ExposedPortRoutesForPlacement(p Placement) map[int]ExposedPortRoute {
	return exposedPortRoutesForPlacement(p)
}
