package mounts

import (
	"context"
	"strconv"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Consumer is a non-root uid/gid that uses a sandbox's mounts: a WASM
// sandbox's worker, which drops to its own uid (pkg/wasm/worker). A FUSE
// tool lets only the uid that mounted it (root) in unless told otherwise,
// so for a consumer the s3 and rclone tools are started allowing other
// users and showing the files as the consumer's, readable by it alone:
// --allow-other with --uid/--gid and owner-only modes. Nobody else reaches
// the mount by name anyway: its parent folders are root's, and the worker
// gets the mount's root folder as a descriptor sandboxd opened.
//
// sshfs already allows other users and checks access on the server, as the
// SSH user. An NFS mount is checked on the server too, now against the
// consumer's uid instead of root's.
type Consumer struct {
	UID int
	GID int
}

type consumerKey struct{}

// WithConsumer makes the mounts started under ctx usable by c.
func WithConsumer(ctx context.Context, c Consumer) context.Context {
	if c.UID <= 0 || c.GID <= 0 {
		return ctx
	}
	return context.WithValue(ctx, consumerKey{}, c)
}

func consumerFrom(ctx context.Context) (Consumer, bool) {
	if ctx == nil {
		return Consumer{}, false
	}
	c, ok := ctx.Value(consumerKey{}).(Consumer)
	return c, ok
}

// fuseForRootOnly reports whether a mount of type t, started with no
// consumer, lets only root in: the s3 and rclone tools do; sshfs runs with
// allow_other, and NFS is checked on the server.
func fuseForRootOnly(t models.MountType) bool {
	return t == models.MountTypeS3 || t == models.MountTypeRclone
}

// consumerArgv adds c's options to a FUSE tool's argv, ahead of the "--"
// that ends its options. Types other than s3 and rclone are unchanged.
func consumerArgv(t models.MountType, argv []string, c Consumer) []string {
	var opts []string
	uid, gid := strconv.Itoa(c.UID), strconv.Itoa(c.GID)
	switch t {
	case models.MountTypeS3:
		opts = []string{"--allow-other", "--uid", uid, "--gid", gid, "--dir-mode", "0700", "--file-mode", "0600"}
	case models.MountTypeRclone:
		opts = []string{"--allow-other", "--uid=" + uid, "--gid=" + gid, "--umask=077"}
	default:
		return argv
	}
	for i, a := range argv {
		if a == "--" {
			out := make([]string, 0, len(argv)+len(opts))
			out = append(out, argv[:i]...)
			out = append(out, opts...)
			return append(out, argv[i:]...)
		}
	}
	return append(argv, opts...)
}
