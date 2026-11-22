package rootd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// Part "image_user" (M1 PR 7, plan §3.3 "Images"): the user a container's
// image runs as. In privilege mode single, containerd's
// oci.WithImageConfig reads the image's /etc/passwd and /etc/group as root
// from the container's snapshot. In split mode the agent cannot read the
// snapshotter's folders, so the helper does it:
//
//   - The snapshot is the container's own, read from containerd by the
//     helper, in its namespace and under its snapshotter (snapshot.go).
//   - Only the image's layers are read, never the container's writable
//     layer (rootpolicy.ImageLayers), each a layer folder under the
//     snapshotter's root.
//   - They are mounted read-only, nosuid, nodev and noexec, in a mount
//     namespace of one thread's own, which ends with the read: the mount
//     is never seen on the host, and is gone even if the helper dies
//     (imageuser_linux.go).
//   - The two files are opened inside the mounted root, so no link in the
//     image reaches a host file (openat2 RESOLVE_IN_ROOT); a file that is
//     not a regular one is never read (a FIFO must not hold the helper),
//     at most maxUserFileBytes are read, and the whole read is bounded in
//     time.
//   - What the files say is resolved by containerd's own code
//     (oci.WithUser, oci.WithAdditionalGIDs), on a copy of the two files,
//     so the answer is what single mode would set, byte for byte.
//
// The answer is cached by what the helper read from containerd itself:
// the snapshot's parent (the image's chain ID) and its layer folders,
// whose numbers the snapshotter never reuses, plus the user string. A
// value the agent claims is never part of the key, so no request can file
// one image's answer under another's.
//
// An image's own files are the tenant's: an image whose /etc/passwd is a
// FIFO, is too big, or names no such user fails the create, as in single
// mode, and is no refusal. A snapshot that is not the container's is.

// maxUserFileBytes is containerd's own bound on an image's passwd and
// group files (pkg/oci maxUserFileBytes).
const maxUserFileBytes = 10 << 20

// imageUserTimeout bounds one read of an image's files; imageUserReads
// bounds how many run at once (each holds a thread of its own).
var (
	imageUserTimeout = 5 * time.Second
	imageUserReads   = make(chan struct{}, 8)
)

// UserFile is one of an image's user files as the helper found it.
type UserFile struct {
	// Present: the file exists in the image.
	Present bool
	// Body is its content, when it is a regular file of a sane size.
	Body []byte
	// Bad says why it is not read: not a regular file, too big, or a
	// path the kernel would not resolve. containerd refuses such a file
	// only when it reads it, so the resolution below does the same.
	Bad string
}

// UserFiles are an image's /etc/passwd and /etc/group.
type UserFiles struct{ Passwd, Group UserFile }

// ImageFileReader reads an image's user files from its layer folders, top
// first (Options.ReadImageFiles). The helper's own mounts them in a
// private mount namespace (imageuser_linux.go); tests read a tree.
type ImageFileReader func(ctx context.Context, snapshotsDir, mountpoint string, layers []string) (UserFiles, error)

// userCache keeps resolved image users; a fixed bound, cleared when full.
type userCache struct {
	mu sync.Mutex
	m  map[string]*rootdpb.ImageUserAnswer
}

const maxCachedUsers = 4096

func (c *userCache) get(key string) (*rootdpb.ImageUserAnswer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[key]
	return a, ok
}

func (c *userCache) put(key string, a *rootdpb.ImageUserAnswer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= maxCachedUsers {
		c.m = map[string]*rootdpb.ImageUserAnswer{}
	}
	c.m[key] = a
}

// imageUserKey is the cache key: what the helper read from containerd,
// and the user.
func imageUserKey(info SnapshotInfo, layers []string, user string) string {
	return info.Parent + "\x00" + strings.Join(layers, ":") + "\x00" + user
}

// imageUser resolves part image_user for container id.
func (c *containerCalls) imageUser(ctx context.Context, id, user string) (*rootdpb.ImageUserAnswer, error) {
	ms, info, err := c.activeSnapshot(ctx, id)
	if err != nil {
		return nil, err
	}
	layers, err := rootpolicy.ImageLayers(c.policy, ms)
	if err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	key := imageUserKey(info, layers, user)
	if a, ok := c.users.get(key); ok {
		return a, nil
	}
	rctx, cancel := context.WithTimeout(ctx, imageUserTimeout)
	defer cancel()
	select {
	case imageUserReads <- struct{}{}:
	case <-rctx.Done():
		return nil, imageUserErr("waiting for a turn to read the image's users: %v", rctx.Err())
	}
	files, err := c.readImageFiles(rctx, c.snapshotsDir, c.mountpoint, layers)
	<-imageUserReads
	if err != nil {
		return nil, imageUserErr("read the image's users: %v", err)
	}
	a, err := resolveImageUser(ctx, files, user)
	if err != nil {
		return nil, imageUserErr("%v", err)
	}
	c.users.put(key, a)
	return a, nil
}

// imageUserErr is an image's own problem: FailedPrecondition, no refusal.
func imageUserErr(format string, args ...any) error {
	return &fileError{code: codes.FailedPrecondition, msg: "root helper: image user: " + fmt.Sprintf(format, args...)}
}

// resolveImageUser resolves user against an image's files with
// containerd's own code, exactly as oci.WithImageConfig does it: WithUser
// then WithAdditionalGIDs for the user's uid, or WithAdditionalGIDs("root")
// for an image that names no user. The files are copied into a private
// temporary root first. A file the reader would not take is a folder
// there, which containerd refuses when, and only when, it reads it.
func resolveImageUser(ctx context.Context, f UserFiles, user string) (*rootdpb.ImageUserAnswer, error) {
	dir, err := os.MkdirTemp("", "aerolvm-imageuser-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Mkdir(filepath.Join(dir, "etc"), 0o700); err != nil {
		return nil, err
	}
	for name, uf := range map[string]UserFile{"passwd": f.Passwd, "group": f.Group} {
		p := filepath.Join(dir, "etc", name)
		switch {
		case !uf.Present:
		case uf.Bad != "":
			if err := os.Mkdir(p, 0o700); err != nil {
				return nil, err
			}
		default:
			if err := os.WriteFile(p, uf.Body, 0o600); err != nil {
				return nil, err
			}
		}
	}
	s := &oci.Spec{Process: &specs.Process{}, Linux: &specs.Linux{}, Root: &specs.Root{Path: dir}}
	c := &containers.Container{}
	if user != "" {
		if err := oci.WithUser(user)(ctx, nil, c, s); err != nil {
			return nil, err
		}
		err = oci.WithAdditionalGIDs(strconv.FormatInt(int64(s.Process.User.UID), 10))(ctx, nil, c, s)
	} else {
		err = oci.WithAdditionalGIDs("root")(ctx, nil, c, s)
	}
	if err != nil {
		return nil, err
	}
	u := s.Process.User
	return &rootdpb.ImageUserAnswer{Uid: u.UID, Gid: u.GID, AdditionalGids: u.AdditionalGids}, nil
}
