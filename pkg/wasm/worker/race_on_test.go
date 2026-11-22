//go:build race

package worker

// raceEnabled is true when the tests run under -race, which runs more of
// the runtime's own threads.
const raceEnabled = true
