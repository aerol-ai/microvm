//go:build linux

package rootd

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// layoutEnv set to "require" makes TestRootProgramsOnThisHostsLayout check
// every path, failing on one this host lacks; scripts/rootd-program-layouts.sh
// sets it in each distribution's image, after it installs e2fsprogs and
// iproute2 and puts placeholders where firecracker, the jailer, runsc and
// workerd go. Unset (the CI runner), a path this host lacks is skipped.
const layoutEnv = "AEROL_ROOT_PROGRAM_LAYOUT"

// TestRootProgramsOnThisHostsLayout runs the helper's own start check
// (checkRootBinaryFile, then the agent-folder rule on the file a link
// names) on every program path the helper and the deploy tools give it for
// split (splitProgramsFile), on this host's real files. Distributions ship
// programs as links (mkfs.ext4 -> mke2fs on Ubuntu and Debian) and put
// them in different places (ip), so a test of temporary files alone says
// nothing about them.
func TestRootProgramsOnThisHostsLayout(t *testing.T) {
	require := os.Getenv(layoutEnv) == "require"
	agentDirs := []string{defaultRunDir, defaultMountsRoot, defaultCredDir, filepath.Dir(defaultDBPath)}
	who := map[string][]string{}
	for tool, programs := range splitPrograms(t) {
		for setting, p := range programs {
			who[p] = append(who[p], tool+" "+setting)
		}
	}
	paths := make([]string, 0, len(who))
	for p := range who {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		slices.Sort(who[p])
		t.Run(p, func(t *testing.T) {
			if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) && !require {
				t.Skipf("this host has no %s", p)
			}
			file, err := checkRootBinaryFile(p)
			if err == nil && file != p {
				err = CheckRootProgramPath(file, agentDirs)
			}
			if err != nil {
				t.Fatalf("the helper refuses %s (%s) on this host: %v", p, strings.Join(who[p], ", "), err)
			}
			if filepath.Base(p) == "mkfs.ext4" {
				// What the helper runs: the path given, and the file it names
				// (mke2fs on Ubuntu and Debian, which an operator may name),
				// each with the helper's own arguments, making ext4.
				for _, prog := range slices.Compact([]string{p, file}) {
					makesExt4(t, prog)
				}
			}
		})
	}
	// ip has no path every distribution shares (/usr/bin/ip on Ubuntu and
	// Debian, where /usr/sbin/ip is a link to it; /usr/sbin/ip on Amazon
	// Linux 2023), so no tool names one, and the refusals say to name the
	// path `readlink -f` prints: that path passes.
	t.Run("ip by readlink -f", func(t *testing.T) {
		found, err := exec.LookPath("ip")
		if err != nil {
			if require {
				t.Fatal(err)
			}
			t.Skip("this host has no ip")
		}
		real, err := filepath.EvalSymlinks(found)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checkRootBinaryFile(real); err != nil {
			t.Fatalf("the helper refuses ip at %s (readlink -f %s): %v", real, found, err)
		}
	})
}

// makesExt4 runs prog with the helper's arguments for an empty filesystem
// (mkfsArgs) and checks the image is ext4: the ext2 magic, and extents, which ext2
// and ext3 lack.
func makesExt4(t *testing.T, prog string) {
	t.Helper()
	img := filepath.Join(t.TempDir(), "overlay.ext4")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 16<<20); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(prog, mkfsArgs(img, "", 0)...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", prog, mkfsArgs(img, "", 0), err, out)
	}
	raw, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	const sb = 1024
	magic := binary.LittleEndian.Uint16(raw[sb+0x38:])
	incompat := binary.LittleEndian.Uint32(raw[sb+0x60:])
	const extents = 0x40
	if magic != 0xef53 || incompat&extents == 0 {
		t.Fatalf("%s made no ext4 (magic %#x, incompat features %#x)", prog, magic, incompat)
	}
}
