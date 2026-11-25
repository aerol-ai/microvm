package rootd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkReserveJail is what the V8 jail limit adds when a new group
// starts: one listing of the jail folder, under the limit's lock, with as
// many jails as a node may hold (the default limit's 4096 at most).
func BenchmarkReserveJail(b *testing.B) {
	for _, n := range []int{10, 544, 4095} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := testHostsConfig(b)
			if err := os.MkdirAll(cfg.Workerd.Jail.ChrootBase, 0o755); err != nil {
				b.Fatal(err)
			}
			for i := range n {
				if err := os.Mkdir(filepath.Join(cfg.Workerd.Jail.ChrootBase, fmt.Sprintf("g%d", i)), 0o755); err != nil {
					b.Fatal(err)
				}
			}
			w := newWorkerdHosts(cfg.Workerd, cfg.LogPath)
			b.ResetTimer()
			for range b.N {
				done, err := w.reserveJail("new")
				if err != nil {
					b.Fatal(err)
				}
				done()
			}
		})
	}
}
