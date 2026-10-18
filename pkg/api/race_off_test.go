//go:build !race

package api

// raceEnabled is true when the tests run under -race, which skews timings.
const raceEnabled = false
