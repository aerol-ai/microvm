//go:build race

package cluster

// raceEnabled is true when the tests run under -race, which skews timings.
const raceEnabled = true
