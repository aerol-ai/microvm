package runloop

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// liveStream opens an output stream over a real connection, so chunks can be
// read while the handler is still writing them, and delivers each on the
// returned channel. The channel closes when the stream ends.
func liveStream(t *testing.T, env *testEnv, path string) <-chan executionUpdateChunk {
	t.Helper()
	server := httptest.NewServer(env.handler)
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+devboxesPath+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status %d", resp.StatusCode)
	}
	chunks := make(chan executionUpdateChunk, 64)
	go func() {
		defer close(chunks)
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for scanner.Scan() {
			data, ok := strings.CutPrefix(scanner.Text(), "data: ")
			if !ok {
				continue
			}
			var chunk executionUpdateChunk
			if json.Unmarshal([]byte(data), &chunk) == nil {
				chunks <- chunk
			}
		}
	}()
	return chunks
}

func nextChunk(t *testing.T, chunks <-chan executionUpdateChunk, what string) executionUpdateChunk {
	t.Helper()
	select {
	case chunk, ok := <-chunks:
		if !ok {
			t.Fatalf("stream ended before %s", what)
		}
		return chunk
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	return executionUpdateChunk{}
}

// runningCommand puts a command that has written stdout and stderr, and has
// not exited, into a fresh plain execution's session.
func runningCommand(t *testing.T, env *testEnv, devboxID, key, stdout, stderr string) (execRef, *fakeCommand) {
	t.Helper()
	ref := execRef{session: plainSession(devboxID, key)}
	if _, _, err := env.h.claimLedger(context.Background(), ledgerKey(devboxID, ref)); err != nil {
		t.Fatal(err)
	}
	cmd := &fakeCommand{id: "00000000000000a1", command: "serve", stdout: stdout, stderr: stderr}
	env.toolbox.mu.Lock()
	env.toolbox.sessions[ref.session] = &fakeSession{commands: []*fakeCommand{cmd}}
	env.toolbox.mu.Unlock()
	return ref, cmd
}

// The SDK's log callbacks fire as a command writes, not when it exits: a
// stream opened on a running command sends what it has written so far, then
// each new write, and its offsets run on into the final output, so the end
// of the command neither repeats nor skips a byte.
func TestStreamDeliversOutputWhileRunning(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &liveOutputMax, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	ref, cmd := runningCommand(t, env, devbox.ID, "live", "ready\n", "warn\n")
	chunks := liveStream(t, env, "/"+devbox.ID+"/executions/"+ref.id()+"/stream_stdout_updates")

	if got := nextChunk(t, chunks, "output written before the stream opened"); got.Output != "ready\n" || got.Offset != 6 {
		t.Fatalf("first chunk = %+v", got)
	}
	env.toolbox.mu.Lock()
	cmd.stdout += "more\n"
	env.toolbox.mu.Unlock()
	if got := nextChunk(t, chunks, "a later write"); got.Output != "more\n" || got.Offset != 11 {
		t.Fatalf("second chunk = %+v", got)
	}
	exit := int32(0)
	env.toolbox.mu.Lock()
	cmd.stdout += "bye"
	cmd.exitCode = &exit
	env.toolbox.mu.Unlock()
	var rest strings.Builder
	last := int64(11)
	for chunk := range chunks {
		if chunk.Offset <= last {
			t.Fatalf("offset went back: %+v after %d", chunk, last)
		}
		rest.WriteString(chunk.Output)
		last = chunk.Offset
	}
	if rest.String() != "bye" || last != 14 {
		t.Fatalf("after exit the stream sent %q ending at %d; want just the rest", rest.String(), last)
	}
}

// A client reconnecting with the offset it last saw resumes there, while the
// command is still running; the stderr stream carries stderr only.
func TestStreamResumesFromItsOffsetWhileRunning(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	ref, cmd := runningCommand(t, env, devbox.ID, "resume", "ready\n", "warn\n")
	defer func() {
		exit := int32(0)
		env.toolbox.mu.Lock()
		cmd.exitCode = &exit
		env.toolbox.mu.Unlock()
	}()
	path := "/" + devbox.ID + "/executions/" + ref.id()
	if got := nextChunk(t, liveStream(t, env, path+"/stream_stdout_updates?offset=3"), "the resumed tail"); got.Output != "dy\n" || got.Offset != 6 {
		t.Fatalf("resumed chunk = %+v", got)
	}
	if got := nextChunk(t, liveStream(t, env, path+"/stream_stderr_updates"), "stderr"); got.Output != "warn\n" || got.Offset != 5 {
		t.Fatalf("stderr chunk = %+v", got)
	}
}

// A burst larger than one read arrives as consecutive chunks, each read
// bounded, before the command exits.
func TestStreamSendsALargeBurstInBoundedReads(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	burst := strings.Repeat("x", 2*maxCapturedStream+100)
	ref, cmd := runningCommand(t, env, devbox.ID, "burst", burst, "")
	defer func() {
		exit := int32(0)
		env.toolbox.mu.Lock()
		cmd.exitCode = &exit
		env.toolbox.mu.Unlock()
	}()
	chunks := liveStream(t, env, "/"+devbox.ID+"/executions/"+ref.id()+"/stream_stdout_updates")
	var got int64
	for got < int64(len(burst)) {
		chunk := nextChunk(t, chunks, "the rest of the burst")
		if len(chunk.Output) > maxCapturedStream || chunk.Offset != got+int64(len(chunk.Output)) {
			t.Fatalf("chunk of %d bytes at offset %d after %d", len(chunk.Output), chunk.Offset, got)
		}
		got = chunk.Offset
	}
}

// A toolbox from before live output sends a running command's output only
// once it ends, so the stream does too — all of it, nothing lost.
func TestStreamFromAnOlderToolboxWaitsForTheExit(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	env.toolbox.mu.Lock()
	env.toolbox.legacyLogs = true
	env.toolbox.mu.Unlock()
	ref, cmd := runningCommand(t, env, devbox.ID, "legacy", "", "")
	chunks := liveStream(t, env, "/"+devbox.ID+"/executions/"+ref.id()+"/stream_stdout_updates")
	select {
	case chunk := <-chunks:
		t.Fatalf("an older toolbox's stream sent %+v before the exit", chunk)
	case <-time.After(300 * time.Millisecond):
	}
	exit := int32(0)
	env.toolbox.mu.Lock()
	cmd.stdout, cmd.exitCode = "all at once\n", &exit
	env.toolbox.mu.Unlock()
	if got := nextChunk(t, chunks, "the output at exit"); got.Output != "all at once\n" || got.Offset != 12 {
		t.Fatalf("chunk = %+v", got)
	}
}

// A read never ends inside a character, so a character that straddles the
// read limit arrives whole in the next read, and the offsets count the
// output's own bytes: the reads together are the output, byte for byte.
func TestLiveOutputKeepsCharactersWhole(t *testing.T) {
	env := newTestEnv(t)
	devbox := env.mustCreate(t, "")
	output := strings.Repeat("x", maxCapturedStream-1) + "\U0001F642END"
	ref, cmd := runningCommand(t, env, devbox.ID, "unicode", output, "")
	var got strings.Builder
	var offset int64
	for reads := 0; offset < int64(len(output)); reads++ {
		text, end, total, supported, err := env.h.liveOutput(context.Background(), devbox.ID, ref.session, cmd.id, false, offset, maxCapturedStream)
		if err != nil || !supported || end <= offset || total != int64(len(output)) || reads > 2 {
			t.Fatalf("read from %d = %q end %d total %d (%v, %v)", offset, text, end, total, supported, err)
		}
		if !utf8.ValidString(text) || int64(len(text)) != end-offset {
			t.Fatalf("read from %d sent %q for %d bytes", offset, text, end-offset)
		}
		got.WriteString(text)
		offset = end
	}
	if got.String() != output {
		t.Fatalf("reads delivered %d bytes ending %q; want the output", got.Len(), got.String()[maxCapturedStream-4:])
	}
}

// The stream counts the command's own bytes. A character the command has
// only half written waits for its other half instead of going out broken,
// and a byte that is not UTF-8 goes out as one '?', so the offsets a client
// resumes from stay true.
func TestStreamCountsTheCommandsBytes(t *testing.T) {
	env := newTestEnv(t)
	shorten(t, &liveOutputMax, 20*time.Millisecond)
	devbox := env.mustCreate(t, "")
	const smile = "\U0001F642"
	ref, cmd := runningCommand(t, env, devbox.ID, "bytes", "a\xffb", "")
	chunks := liveStream(t, env, "/"+devbox.ID+"/executions/"+ref.id()+"/stream_stdout_updates")
	if got := nextChunk(t, chunks, "the first write"); got.Output != "a?b" || got.Offset != 3 {
		t.Fatalf("first chunk = %+v", got)
	}
	env.toolbox.mu.Lock()
	cmd.stdout += "ok" + smile[:2]
	env.toolbox.mu.Unlock()
	if got := nextChunk(t, chunks, "the whole characters"); got.Output != "ok" || got.Offset != 5 {
		t.Fatalf("second chunk = %+v; want the half-written character held back", got)
	}
	exit := int32(0)
	env.toolbox.mu.Lock()
	cmd.stdout += smile[2:]
	cmd.exitCode = &exit
	env.toolbox.mu.Unlock()
	var rest strings.Builder
	last := int64(5)
	for chunk := range chunks {
		rest.WriteString(chunk.Output)
		last = chunk.Offset
	}
	if rest.String() != smile || last != 9 {
		t.Fatalf("after exit the stream sent %q ending at %d; want the character, ending at 9", rest.String(), last)
	}
}
