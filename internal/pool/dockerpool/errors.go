package dockerpool

import "errors"

// ErrNoSlot is returned when no warm slot is available for the key.
var ErrNoSlot = errors.New("docker pool: no slot")

// ErrStaleImage is returned when a parked slot's image ID no longer matches.
var ErrStaleImage = errors.New("docker pool: stale image")
