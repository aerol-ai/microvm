package proc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
)

// The test binary doubles as a fake driver: Launch runs it with
// AEROL_FAKE_DRIVER=1 and it speaks the protocol from Go, so the kernel's
// framing, markers and failure paths are tested exactly and without an
// interpreter installed.
func TestFakeDriverProcess(t *testing.T) {
	if os.Getenv("AEROL_FAKE_DRIVER") != "1" {
		return
	}
	os.Exit(runFakeDriver())
}

func runFakeDriver() int {
	ev := os.NewFile(4, "events")
	req := os.NewFile(3, "requests")
	nonce := os.Getenv("AEROL_INTERP_NONCE")
	switch os.Getenv("AEROL_FAKE_MODE") {
	case "fatal":
		_ = codeinterp.WriteFrame(ev, "FATAL", []byte("cannot set up\n"))
		return 1
	case "exit":
		fmt.Fprintln(os.Stderr, "driver broke: bad interpreter")
		return 1
	case "silent-exit":
		return 7
	case "hang":
		time.Sleep(time.Minute)
		return 0
	case "early":
		_ = codeinterp.WriteFrame(ev, "COUNT", []byte("1"))
		time.Sleep(time.Minute)
		return 0
	case "env":
		// Launch-time environment, for the env test.
		_ = codeinterp.WriteFrame(ev, "READY", []byte("1"))
		pwd, _ := os.Getwd()
		// To stderr: an idle kernel keeps the stderr tail, which the test reads.
		fmt.Fprintf(os.Stderr, "cwd=%s mode=%s mpl=%s unbuf=%s ctx=%s nonce=%d\n", pwd, os.Getenv("AEROL_INTERP_MODE"),
			os.Getenv("MPLBACKEND"), os.Getenv("PYTHONUNBUFFERED"), os.Getenv("CTX_VAR"), len(nonce))
		time.Sleep(time.Minute)
		return 0
	}

	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, os.Interrupt)
	_ = codeinterp.WriteFrame(ev, "READY", []byte("1"))

	seq := 0
	marker := func() []byte {
		seq++
		return []byte("\x1e" + nonce + ":" + strconv.Itoa(seq) + "\x1e")
	}
	sync := func() {
		m := marker()
		_, _ = os.Stdout.Write(m)
		_, _ = os.Stderr.Write(m)
		_ = codeinterp.WriteFrame(ev, "SYNC", []byte(strconv.Itoa(seq)))
	}
	slowSync := func() {
		m := marker()
		for _, f := range []*os.File{os.Stdout, os.Stderr} {
			for _, b := range m {
				_, _ = f.Write([]byte{b})
				time.Sleep(2 * time.Millisecond)
			}
		}
		_ = codeinterp.WriteFrame(ev, "SYNC", []byte(strconv.Itoa(seq)))
	}

	fr := codeinterp.NewFrameReader(req)
	var env []string
	count := 0
	for {
		if os.Getenv("AEROL_FAKE_MODE") == "slowread" {
			// Busy between runs: a request waits in the pipe a while
			// before the driver reads it.
			time.Sleep(300 * time.Millisecond)
		}
		kind, payload, err := fr.Read()
		if err != nil {
			return 0
		}
		switch kind {
		case "QUIT":
			return 0
		case "ENV":
			env = append(env, string(payload))
			continue
		case "EXEC":
		default:
			continue
		}
		// Like a real driver, a SIGINT that came while idle means nothing:
		// the run takes interrupts from its COUNT on (doc.go).
		for len(sigs) > 0 {
			<-sigs
		}
		count++
		_ = codeinterp.WriteFrame(ev, "COUNT", []byte(strconv.Itoa(count)))
		status := "ok"
		for _, line := range strings.Split(string(payload), "\n") {
			cmd, arg, _ := strings.Cut(line, " ")
			switch cmd {
			case "out":
				fmt.Fprint(os.Stdout, arg)
			case "err":
				fmt.Fprint(os.Stderr, arg)
			case "sync":
				sync()
			case "slowsync":
				slowSync()
			case "result":
				sync()
				_ = codeinterp.WriteFrame(ev, "RESULT", []byte(`{"data":{"text/plain":"42","application/json":{"n":12345678901234567890}},"main":true}`))
			case "badresult":
				sync()
				_ = codeinterp.WriteFrame(ev, "RESULT", []byte(`{not json`))
			case "text":
				sync()
				_ = codeinterp.WriteFrame(ev, "TEXT", []byte(arg))
			case "error":
				sync()
				_ = codeinterp.WriteFrame(ev, "ERROR", []byte("ValueError\x1fbad value\x1fTraceback: here"))
			case "stdioframes":
				_ = codeinterp.WriteFrame(ev, "OUT", []byte("o"))
				_ = codeinterp.WriteFrame(ev, "ERR", []byte("e"))
				_ = codeinterp.WriteFrame(ev, "WHATEVER", []byte("ignored"))
				_ = codeinterp.WriteFrame(ev, "COUNT", []byte("not a number"))
			case "utf8split":
				b := []byte("é")
				_, _ = os.Stdout.Write(b[:1])
				time.Sleep(30 * time.Millisecond)
				_, _ = os.Stdout.Write(append(b[1:], '\n'))
			case "big":
				n, _ := strconv.Atoi(arg)
				var sb strings.Builder
				for i := 0; sb.Len() < n; i++ {
					fmt.Fprintf(&sb, "%07d\n", i)
				}
				_, _ = os.Stdout.WriteString(sb.String()[:n])
			case "env":
				sort.Strings(env)
				fmt.Fprint(os.Stdout, strings.Join(env, ","))
			case "sleep":
				d, err := time.ParseDuration(arg)
				if err != nil {
					d = 20 * time.Second
				}
				select {
				case <-sigs:
					status = "interrupted"
				case <-time.After(d):
				}
			case "ignore":
				signal.Ignore(os.Interrupt)
				time.Sleep(time.Minute)
			case "die":
				fmt.Fprint(os.Stderr, "dying")
				os.Exit(3)
			case "closeevents":
				_ = ev.Close()
				time.Sleep(time.Minute)
			case "syncnomarker":
				// Announce a marker that never comes, then die.
				_ = codeinterp.WriteFrame(ev, "SYNC", []byte(strconv.Itoa(seq+1)))
				time.Sleep(50 * time.Millisecond)
				os.Exit(0)
			case "badsync":
				_ = codeinterp.WriteFrame(ev, "SYNC", []byte("x"))
				time.Sleep(time.Minute)
			case "bgexit":
				// A background child keeps stdout open after the driver dies.
				bg := exec.Command("sleep", "30")
				bg.Stdout = os.Stdout
				_ = bg.Start()
				fmt.Fprint(os.Stdout, "bye")
				os.Exit(0)
			case "status":
				status = arg
			}
		}
		env = nil
		sync()
		_ = codeinterp.WriteFrame(ev, "DONE", []byte(status))
		if strings.Contains(string(payload), "strayexit") {
			// A frame nobody asked for, then death between runs.
			_ = codeinterp.WriteFrame(ev, "COUNT", []byte("99"))
			os.Exit(0)
		}
	}
}

// fakeDriver is a driver that runs this test binary.
func fakeDriver(t *testing.T, mode string) drivers.Driver {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return drivers.Driver{
		Language: codeinterp.LangPython,
		Programs: []string{self},
		FileName: "fake.txt",
		Script:   []byte("fake driver " + mode),
		Args: func(program, script string) []string {
			return []string{program, "-test.run=^TestFakeDriverProcess$", "-test.count=1"}
		},
		Env: map[string]string{"AEROL_FAKE_DRIVER": "1", "AEROL_FAKE_MODE": mode},
	}
}

func useFakeDriver(t *testing.T, mode string) {
	t.Helper()
	d := fakeDriver(t, mode)
	prev := lookupDriver
	lookupDriver = func(lang string) (drivers.Driver, bool) {
		if lang == codeinterp.LangPython {
			return d, true
		}
		return drivers.Driver{}, false
	}
	t.Cleanup(func() { lookupDriver = prev })
}

func launchFake(t *testing.T, mode string) *kernel {
	t.Helper()
	useFakeDriver(t, mode)
	l := New(Config{DriverDir: t.TempDir()})
	k, err := l.Launch(context.Background(), codeinterp.Spec{Language: codeinterp.LangPython, Cwd: t.TempDir()})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k.(*kernel)
}

// events collects a run's events.
type events struct {
	mu  sync.Mutex
	all []codeinterp.Event
}

func (e *events) sink(ev codeinterp.Event) {
	e.mu.Lock()
	e.all = append(e.all, ev)
	e.mu.Unlock()
}

func (e *events) list() []codeinterp.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]codeinterp.Event(nil), e.all...)
}

// stream concatenates stdout (or stderr) events.
func (e *events) stream(kind codeinterp.EventKind) string {
	var sb strings.Builder
	for _, ev := range e.list() {
		if ev.Kind == kind {
			sb.WriteString(ev.Text)
		}
	}
	return sb.String()
}

// trace renders events compactly so a test can assert their order.
func (e *events) trace() []string {
	var out []string
	for _, ev := range e.list() {
		switch ev.Kind {
		case codeinterp.EventCount:
			out = append(out, "count:"+strconv.Itoa(ev.Count))
		case codeinterp.EventStdout:
			out = append(out, "out:"+ev.Text)
		case codeinterp.EventStderr:
			out = append(out, "err:"+ev.Text)
		case codeinterp.EventResult:
			out = append(out, fmt.Sprintf("result:%v:%v", ev.Bundle["text/plain"], ev.Main))
		case codeinterp.EventError:
			out = append(out, "error:"+ev.ErrName+":"+ev.ErrValue)
		}
	}
	return out
}

func execute(t *testing.T, k codeinterp.Kernel, code string, env map[string]string) (codeinterp.Outcome, *events) {
	t.Helper()
	ev := &events{}
	done := make(chan codeinterp.Outcome, 1)
	go func() {
		out, err := k.Execute(codeinterp.Request{Code: code, Env: env}, ev.sink)
		if err != nil {
			t.Errorf("Execute: %v", err)
		}
		done <- out
	}()
	select {
	case out := <-done:
		return out, ev
	case <-time.After(30 * time.Second):
		t.Fatalf("Execute(%q) did not return; events so far %v", code, ev.trace())
	}
	return codeinterp.Outcome{}, nil
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not happen", what)
	}
}

func processGone(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == syscall.ESRCH
}
