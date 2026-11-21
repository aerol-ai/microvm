package rootd

import (
	"fmt"
	"net"
	"os"

	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// The rules for the helper's folders and socket live in internal/rootfolder,
// which the runtime supervisor shares: when the supervisor runs the helper,
// it makes the socket itself and hands it to each helper it starts, so a
// swapped-in helper serves the same socket (eng review D4, outside review
// O6). The names below keep the helper's code as it reads.

// folderFlags open a folder for its handle alone, refusing a link.
const folderFlags = rootfolder.FolderFlags

// listen makes the helper's socket at path, mode 0660, group gid
// (rootfolder.Listen), when the helper runs on its own and no supervisor
// passed it one.
func listen(path string, gid int) (*net.UnixListener, os.FileInfo, error) {
	ln, fi, err := rootfolder.Listen(path, gid)
	if err != nil {
		return nil, nil, fmt.Errorf("root helper: %w", err)
	}
	return ln, fi, nil
}

// openFolder opens dir with no link followed, making it where missing,
// and checks that only root can change it (rootfolder.OpenFolder).
func openFolder(dir string) (int, error) { return rootfolder.OpenFolder(dir) }

var (
	walkFolder = rootfolder.WalkFolder
	tmpName    = rootfolder.TmpName
	isTmpName  = rootfolder.IsTmpName
)
