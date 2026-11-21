package netns

import "github.com/aerol-ai/microvm/internal/network/nsbuild"

// The in-process namespace steps (nsbuild): the same ones the root helper
// runs in privilege mode split.
var (
	createNamedNetns = nsbuild.CreateNamed
	loopbackUpIn     = nsbuild.LoopbackUp
	deleteNamedNetns = nsbuild.DeleteNamed
)
