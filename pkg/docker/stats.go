package docker

import (
	"context"
	"net/http"
	"net/url"
)

// ContainerStat is a one-shot resource snapshot for a container: the cumulative
// CPU time consumed since it started and its current working-set memory. The
// CPU figure is a monotonic counter; callers difference it across reads to get
// CPU time consumed in a window. Memory is an instantaneous gauge.
type ContainerStat struct {
	CPUTotalNanos uint64 // cumulative CPU time (ns) consumed since container start
	MemBytes      uint64 // current working-set memory in bytes
}

// containerStatsResponse is the subset of Docker's /stats payload we read. We
// request a one-shot (stream=false) snapshot and compute our own deltas across
// reads, so only the cumulative CPU counter and the current memory gauge matter;
// Docker's own precpu_stats / percentage fields are ignored.
type containerStatsResponse struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
	} `json:"cpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Stats struct {
			InactiveFile uint64 `json:"inactive_file"`
		} `json:"stats"`
	} `json:"memory_stats"`
}

// ContainerStats returns a one-shot CPU/memory snapshot for a container via the
// Docker stats endpoint with stream=false — a single cheap request that does not
// hold the connection open. Callers (the opt-in live usage sampler) bound how
// often they call it; this method does no rate limiting of its own.
//
// Memory follows `docker stats` working-set semantics: the inactive file cache
// is subtracted so page cache does not inflate the figure.
func (c *Client) ContainerStats(ctx context.Context, containerRef string) (ContainerStat, error) {
	var resp containerStatsResponse
	query := url.Values{"stream": {"false"}}
	path := "/containers/" + url.PathEscape(containerRef) + "/stats"
	if err := c.doJSON(ctx, http.MethodGet, path, query, nil, nil, &resp); err != nil {
		return ContainerStat{}, err
	}
	mem := resp.MemoryStats.Usage
	if resp.MemoryStats.Stats.InactiveFile <= mem {
		mem -= resp.MemoryStats.Stats.InactiveFile
	}
	return ContainerStat{
		CPUTotalNanos: resp.CPUStats.CPUUsage.TotalUsage,
		MemBytes:      mem,
	}, nil
}
