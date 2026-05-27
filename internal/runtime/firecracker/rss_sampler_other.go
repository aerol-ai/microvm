//go:build !linux

package firecracker

// rss_sampler_other.go is the non-linux stub for the RSS sampler.
// Firecracker only runs on linux, but the dev/CI cycle runs `go test`
// on darwin and the runtime package compiles cross-platform. Returning
// zeros here keeps the sampler API uniform without dragging /proc
// references into builds where they wouldn't link.
//
// Mirrors the shape of pkg/capacity/meminfo_other.go.

func readRSSPagesForPID(_ int) (int64, error) { return 0, nil }

func parseStatm(_ []byte) (int64, error) { return 0, nil }
