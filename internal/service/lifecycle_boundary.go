package service

// The lifecycle boundary (review 2 finding 9). Every change to whether one
// sandbox runs happens under one per-sandbox lock, Service.lifecycleLocks:
//
//   - the native start, stop, pause and resume calls, which every facade
//     (Daytona start and stop, E2B pause and connect, Runloop suspend and
//     resume) and the fleet controls go through;
//   - DestroySandbox;
//   - a restart on failure, and a wake by traffic;
//   - the lifecycle sweep's timed stops and deletes, and the disk watchdog's
//     stop;
//   - the die, stop and destroy events, and the restart a crash schedules;
//   - the read-modify-write of the lifecycle timers (D7).
//
// Each step reads the row after it holds the lock and decides from that read,
// so no step acts on a state another one has changed since. A stop that comes
// while a restart on failure is starting the sandbox waits for it and then
// stops it; a restart that comes after a stop finds nothing pending. Before
// this, start, stop and destroy took no lock, so an automatic restart already
// inside the runtime start wrote "started" over a stop that had succeeded.
//
// The public entry points take the lock. The *Locked helpers expect the
// caller to hold it, so a step already inside the boundary (pause calls the
// stop, resume calls the start, the restart calls the start) never takes it
// twice.
//
// Lock order: lifecycleLocks before destroyLocks. DestroySandbox and the
// destroy event both take them in that order.
//
// The lock is one per sandbox, not a shared stripe: a step can hold it across
// a runtime start or stop (seconds, up to restartStartTimeout), and a shared
// stripe would make unrelated sandboxes wait for it. Runtime events wait on
// their sandbox's own event queue (event_queues.go), so a sandbox held by a
// long step never holds up another sandbox's events. Waiting honours ctx, so
// a caller that gives up stops waiting.
// lifecycleLocks is a keyedLocks[string] (keyed_locks.go), taken with lockCtx.
