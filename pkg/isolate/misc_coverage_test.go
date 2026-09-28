package isolate

import (
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
)

// Re-exec as a fake workerd when the env latch is set. Start() spawns
// WorkerdPath; pointing it at the test binary with this env lets offline tests
// cover the spawn → waitReady → Invoke happy path without a real workerd.
// Re-exec as a fake workerd when the env latch is set. Start() spawns
// WorkerdPath; pointing it at the test binary with this env lets offline tests
// cover the spawn → waitReady → Invoke happy path without a real workerd.
func init() {
	if os.Getenv("ISOLATE_FAKE_WORKERD") != "1" {
		return
	}
	runFakeWorkerd()
	os.Exit(0)
}

func runFakeWorkerd() {
	// argv: <testbin> serve --experimental config.capnp
	configPath := os.Args[len(os.Args)-1]
	raw, err := os.ReadFile(configPath)
	if err != nil {
		os.Stderr.WriteString("fake-workerd: read config: " + err.Error() + "\n")
		os.Exit(1)
	}
	// Prefer the sockets[] control entry — host/egress also use unix: addresses.
	re := regexp.MustCompile(`name = "control", address = "unix:([^"]+)"`)
	m := re.FindSubmatch(raw)
	if m == nil {
		os.Stderr.WriteString("fake-workerd: no control unix address in config\n")
		os.Exit(1)
	}
	sock := string(m[1])
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Stderr.WriteString("fake-workerd: listen: " + err.Error() + "\n")
		os.Exit(1)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-echo-sb-id", r.Header.Get("x-sb-id"))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "fake-ok")
	})}
	_ = srv.Serve(ln)
}
