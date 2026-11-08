package main

import (
	"fmt"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// applyAdoptFrame binds a parked agent to the sandbox an adopt frame names
// and returns the ready ack to send back (plans/cluster-phase-2.md §2).
//
// A parked container was started from the pool's spec, which never saw the
// create request, so the sandbox's env arrives in the frame instead of in
// toolboxd's process environment. The order is what makes every user
// process see it:
//
//  1. The env goes into the sandbox env store, which childEnviron lays over
//     os.Environ() for the held-back image command, exec, sessions,
//     terminals and SSH alike.
//  2. Then the identity: servingRequests opens exec and sessions only once
//     the agent is adopted, so none can start before the env is in place.
//  3. The caller sends the ack and only then starts the held command.
//
// An env the store refuses returns an error before anything changes: no
// identity, no ack and no command. The host, waiting for the ack, fails the
// adopt, destroys the slot and creates the sandbox cold, so a sandbox is
// never served with part of its env. Replace (not merge) also means an
// adopt drops any key a previous adopt set and this one does not.
//
// The ack's digest is keyed with the frame's nonce over the env the store
// now holds; the host refuses an ack without it. Nothing here logs the env
// or puts a key or value in an error (sandboxenv.ErrInvalid names neither).
func (s *server) applyAdoptFrame(frame readyproto.AdoptFrame) (readyproto.ReadySignal, error) {
	if _, err := sandboxEnv.Replace(frame.Env); err != nil {
		return readyproto.ReadySignal{}, fmt.Errorf("adopt env: %w", err)
	}
	s.adoptIdentity(frame.SandboxID, frame.Token)
	return readyproto.ReadySignal{
		Event:        readyproto.EventReady,
		SandboxID:    frame.SandboxID,
		Token:        frame.Token,
		Nonce:        frame.Nonce,
		AgentVersion: version.Version,
		EnvDigest:    readyproto.EnvDigest(frame.Nonce, frame.Env),
	}, nil
}
