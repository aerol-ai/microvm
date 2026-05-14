package sshgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/crypto/ssh"
)

func keysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// SandboxLookup is the slice of *service.Service the gateway needs.
type SandboxLookup interface {
	GetSandbox(ctx context.Context, id string) (*models.Sandbox, error)
	TouchSandbox(ctx context.Context, id string) error
}

// DockerExec is the slice of *docker.Client the gateway needs. It exists so
// the gateway can be tested with a fake.
type DockerExec interface {
	ExecCreate(ctx context.Context, containerID string, cmd []string, env []string, workdir string, tty bool) (string, error)
	ExecStart(ctx context.Context, execID string, tty bool) (*docker.ExecSession, error)
	ExecResize(ctx context.Context, execID string, height, width int) error
	ExecInspect(ctx context.Context, execID string) (exitCode int, running bool, err error)
}

// Config carries the gateway's runtime parameters.
type Config struct {
	ListenAddr     string
	HostKeyPath    string
	AcceptDeadline time.Duration
	// ToolboxPort is the in-container HTTP port toolboxd listens on. Used by
	// session-attach mode to dial the WebSocket directly. If zero, session
	// mode is disabled and the gateway falls back to one-shot exec.
	ToolboxPort int
}

// Gateway terminates SSH connections on the host and bridges accepted shell /
// exec sessions to a docker exec stream inside the target sandbox container.
//
// Auth is per-sandbox: every sandbox is created with a freshly generated
// ed25519 keypair, the public key is persisted on the sandbox row, and that
// key is the only one authorized to SSH into that specific sandbox. There is
// no global key.
type Gateway struct {
	logger      *slog.Logger
	listenOn    string
	signer      ssh.Signer
	svc         SandboxLookup
	dockerCli   DockerExec
	toolboxPort int
}

// New constructs a Gateway. It loads or generates the host key. Returns an
// error if the gateway cannot be initialized — callers should treat this as
// fatal.
func New(logger *slog.Logger, cfg Config, svc SandboxLookup, dockerCli DockerExec) (*Gateway, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("ssh listen addr is empty")
	}
	signer, err := LoadOrGenerateHostKey(cfg.HostKeyPath)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		logger:      logger,
		listenOn:    cfg.ListenAddr,
		signer:      signer,
		svc:         svc,
		dockerCli:   dockerCli,
		toolboxPort: cfg.ToolboxPort,
	}, nil
}

// Start opens the TCP listener and accepts connections until ctx is cancelled.
func (g *Gateway) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", g.listenOn)
	if err != nil {
		return fmt.Errorf("ssh listen %s: %w", g.listenOn, err)
	}
	g.logger.Info("ssh gateway listening", "addr", g.listenOn)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			g.logger.Warn("ssh accept failed", "error", err)
			continue
		}
		go g.handleConn(ctx, conn)
	}
}

func (g *Gateway) handleConn(ctx context.Context, nConn net.Conn) {
	remote := nConn.RemoteAddr().String()
	defer func() {
		_ = nConn.Close()
	}()

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: g.publicKeyCallback(ctx),
		MaxAuthTries:      3,
	}
	cfg.AddHostKey(g.signer)

	serverConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		g.logger.Info("ssh handshake failed", "remote", remote, "error", err)
		return
	}
	defer serverConn.Close()

	sandboxID := ""
	mode := "exec"
	sessionName := ""
	if serverConn.Permissions != nil {
		sandboxID = serverConn.Permissions.Extensions["sandbox_id"]
		mode = serverConn.Permissions.Extensions["mode"]
		sessionName = serverConn.Permissions.Extensions["session_name"]
	}
	g.logger.Info("ssh connection accepted", "remote", remote, "sandbox_id", sandboxID, "mode", mode, "session_name", sessionName)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := newChan.Accept()
		if err != nil {
			g.logger.Warn("ssh channel accept failed", "error", err)
			continue
		}
		go g.handleSession(ctx, sandboxID, mode, sessionName, channel, requests)
	}
}

// parseSSHUser splits the SSH username into (sandbox_id, mode, name).
// Forms:
//
//	"<id>"           → mode="session", name="default"
//	"<id>+<name>"    → mode="session", name=<name>
//	"<id>+exec"      → mode="exec" (legacy one-shot via docker exec)
//
// Returns ok=false if the input is empty.
func parseSSHUser(raw string) (sandboxID, mode, name string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", false
	}
	id, suffix, found := strings.Cut(raw, "+")
	id = strings.TrimSpace(id)
	if id == "" {
		return "", "", "", false
	}
	if !found || suffix == "" {
		return id, "session", "default", true
	}
	suffix = strings.TrimSpace(suffix)
	if suffix == "exec" {
		return id, "exec", "", true
	}
	return id, "session", suffix, true
}

func (g *Gateway) publicKeyCallback(ctx context.Context) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		username := strings.TrimSpace(conn.User())
		sandboxID, mode, sessionName, ok := parseSSHUser(username)
		if !ok {
			return nil, errors.New("empty username")
		}
		// Constant-time-ish auth regardless of which side fails: any failure
		// becomes "permission denied" without leaking which step blew up.
		sandbox, err := g.svc.GetSandbox(ctx, sandboxID)
		if err != nil || sandbox == nil {
			g.logger.Info("ssh auth: sandbox lookup failed", "username", username, "error", err)
			return nil, errors.New("permission denied")
		}
		if sandbox.Status != models.SandboxStatusStarted {
			g.logger.Info("ssh auth: sandbox not running", "sandbox_id", sandbox.ID, "status", string(sandbox.Status))
			return nil, errors.New("permission denied")
		}
		if sandbox.ContainerID == "" {
			return nil, errors.New("permission denied")
		}
		if sandbox.SSHPublicKey == "" {
			g.logger.Info("ssh auth: sandbox has no authorized key", "sandbox_id", sandbox.ID)
			return nil, errors.New("permission denied")
		}
		authorized, parseErr := ParseAuthorizedKey(sandbox.SSHPublicKey)
		if parseErr != nil {
			g.logger.Warn("ssh auth: stored authorized key is invalid", "sandbox_id", sandbox.ID, "error", parseErr)
			return nil, errors.New("permission denied")
		}
		if !keysEqual(key, authorized) {
			return nil, errors.New("permission denied")
		}
		return &ssh.Permissions{
			Extensions: map[string]string{
				"sandbox_id":   sandbox.ID,
				"container_id": sandbox.ContainerID,
				"mode":         mode,
				"session_name": sessionName,
			},
		}, nil
	}
}

// handleSession services a single SSH session channel. It implements the
// minimum useful subset of RFC 4254: pty-req, env, shell, exec, window-change,
// and exit-status reporting.
//
// mode: "session" → on shell, attach to/create a named toolboxd session
// (default name "default"). "exec" → behave like the old one-shot path,
// running every shell/exec via docker exec.
func (g *Gateway) handleSession(ctx context.Context, sandboxID, mode, sessionName string, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	sandbox, err := g.svc.GetSandbox(ctx, sandboxID)
	if err != nil || sandbox == nil {
		g.writeStderr(channel, fmt.Sprintf("sandbox unavailable: %v\r\n", err))
		_ = sendExitStatus(channel, 1)
		return
	}
	if sandbox.Status != models.SandboxStatusStarted || sandbox.ContainerID == "" {
		g.writeStderr(channel, fmt.Sprintf("sandbox not running: status=%s\r\n", sandbox.Status))
		_ = sendExitStatus(channel, 1)
		return
	}
	containerID := sandbox.ContainerID

	state := &sessionState{
		envVars: make([]string, 0, 4),
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			term, rows, cols, ok := parsePTYRequest(req.Payload)
			if !ok {
				replyRequest(req, false)
				continue
			}
			state.wantPTY = true
			state.ptyRows = rows
			state.ptyCols = cols
			if term != "" {
				state.envVars = append(state.envVars, "TERM="+term)
			}
			replyRequest(req, true)

		case "env":
			name, value, ok := parseEnvRequest(req.Payload)
			if ok && allowEnvVar(name) {
				state.envVars = append(state.envVars, name+"="+value)
			}
			replyRequest(req, true)

		case "shell":
			replyRequest(req, true)
			if mode == "session" && g.toolboxPort > 0 && sandbox.ContainerIP != "" {
				exitCode := g.attachToSession(ctx, channel, sandbox, sessionName, state)
				_ = sendExitStatus(channel, uint32(exitCode))
				return
			}
			cmd := []string{"sh", "-c", "exec bash -l 2>/dev/null || exec sh -l"}
			g.runExec(ctx, channel, sandboxID, containerID, cmd, state)
			return

		case "exec":
			command, ok := parseExecRequest(req.Payload)
			if !ok || strings.TrimSpace(command) == "" {
				replyRequest(req, false)
				continue
			}
			cmd := []string{"sh", "-c", command}
			replyRequest(req, true)
			g.runExec(ctx, channel, sandboxID, containerID, cmd, state)
			return

		case "window-change":
			rows, cols, ok := parseWindowChange(req.Payload)
			if !ok {
				continue
			}
			state.ptyRows = rows
			state.ptyCols = cols
			if state.execID != "" {
				resizeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := g.dockerCli.ExecResize(resizeCtx, state.execID, int(rows), int(cols)); err != nil {
					g.logger.Debug("exec resize failed", "sandbox_id", sandboxID, "error", err)
				}
				cancel()
			}

		case "subsystem":
			// SFTP would arrive here; not implemented yet.
			replyRequest(req, false)

		default:
			if req.WantReply {
				replyRequest(req, false)
			}
		}
	}
}

type sessionState struct {
	wantPTY bool
	ptyRows uint32
	ptyCols uint32
	envVars []string
	execID  string
}

// runExec starts the docker exec, copies bytes between the SSH channel and
// the hijacked exec stream, and reports the exit code over the SSH channel
// when the process finishes.
func (g *Gateway) runExec(ctx context.Context, channel ssh.Channel, sandboxID, containerID string, cmd []string, state *sessionState) {
	_ = g.svc.TouchSandbox(ctx, sandboxID)

	createCtx, cancelCreate := context.WithTimeout(ctx, 10*time.Second)
	execID, err := g.dockerCli.ExecCreate(createCtx, containerID, cmd, state.envVars, "", state.wantPTY)
	cancelCreate()
	if err != nil {
		g.writeStderr(channel, fmt.Sprintf("failed to start session: %v\r\n", err))
		_ = sendExitStatus(channel, 1)
		return
	}
	state.execID = execID

	session, err := g.dockerCli.ExecStart(ctx, execID, state.wantPTY)
	if err != nil {
		g.writeStderr(channel, fmt.Sprintf("failed to attach session: %v\r\n", err))
		_ = sendExitStatus(channel, 1)
		return
	}
	defer session.Close()

	if state.wantPTY && state.ptyRows > 0 && state.ptyCols > 0 {
		resizeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = g.dockerCli.ExecResize(resizeCtx, execID, int(state.ptyRows), int(state.ptyCols))
		cancel()
	}

	g.pumpStreams(channel, session, state.wantPTY)

	exitCode := 0
	inspectCtx, cancelInspect := context.WithTimeout(ctx, 5*time.Second)
	if code, _, err := g.dockerCli.ExecInspect(inspectCtx, execID); err == nil {
		exitCode = code
	} else {
		g.logger.Debug("exec inspect failed", "sandbox_id", sandboxID, "error", err)
	}
	cancelInspect()

	_ = sendExitStatus(channel, uint32(exitCode))
}

// pumpStreams copies bytes both directions between the SSH channel and the
// hijacked Docker exec stream. Returns when either side closes.
func (g *Gateway) pumpStreams(channel ssh.Channel, session *docker.ExecSession, tty bool) {
	var wg sync.WaitGroup
	wg.Add(2)

	// channel -> exec (stdin)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(session.Conn, channel)
		// Half-close so the process sees EOF on stdin if it cares.
		if cw, ok := session.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// exec -> channel
	go func() {
		defer wg.Done()
		if tty {
			_, _ = io.Copy(channel, session.Reader)
		} else {
			demuxDockerStream(channel, session.Reader)
		}
		// Once the exec side EOFs, signal stdin pump to stop reading by
		// closing the channel for further input.
		_ = channel.CloseWrite()
	}()

	wg.Wait()
}

func (g *Gateway) writeStderr(channel ssh.Channel, msg string) {
	_, _ = channel.Stderr().Write([]byte(msg))
}

// allowEnvVar restricts which env vars an SSH client can inject. We accept the
// usual locale/term-related ones plus anything the user has explicitly opted
// into via the SSH SendEnv config; refusing unfamiliar names keeps the
// container's environment predictable.
func allowEnvVar(name string) bool {
	switch name {
	case "TERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES":
		return true
	}
	return strings.HasPrefix(name, "LC_")
}

func replyRequest(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// sendExitStatus emits an RFC 4254 §6.10 exit-status request so the client
// shows the right exit code (e.g. `ssh host 'exit 7'` → 7).
func sendExitStatus(channel ssh.Channel, status uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], status)
	_, err := channel.SendRequest("exit-status", false, buf[:])
	return err
}

// parsePTYRequest parses an RFC 4254 §6.2 pty-req payload.
// Layout: string TERM, uint32 cols, uint32 rows, uint32 pixwidth, uint32 pixheight, string modes.
func parsePTYRequest(payload []byte) (term string, rows, cols uint32, ok bool) {
	term, rest, ok := readString(payload)
	if !ok {
		return "", 0, 0, false
	}
	if len(rest) < 16 {
		return "", 0, 0, false
	}
	cols = binary.BigEndian.Uint32(rest[0:4])
	rows = binary.BigEndian.Uint32(rest[4:8])
	return term, rows, cols, true
}

// parseEnvRequest parses an RFC 4254 §6.4 env payload: string name, string value.
func parseEnvRequest(payload []byte) (name, value string, ok bool) {
	name, rest, ok := readString(payload)
	if !ok {
		return "", "", false
	}
	value, _, ok = readString(rest)
	return name, value, ok
}

// parseExecRequest parses an RFC 4254 §6.5 exec payload: string command.
func parseExecRequest(payload []byte) (string, bool) {
	cmd, _, ok := readString(payload)
	return cmd, ok
}

// parseWindowChange parses an RFC 4254 §6.7 window-change payload:
// uint32 cols, uint32 rows, uint32 pixwidth, uint32 pixheight.
func parseWindowChange(payload []byte) (rows, cols uint32, ok bool) {
	if len(payload) < 16 {
		return 0, 0, false
	}
	cols = binary.BigEndian.Uint32(payload[0:4])
	rows = binary.BigEndian.Uint32(payload[4:8])
	return rows, cols, true
}

// readString reads an SSH-format string (uint32 length + bytes) from buf.
func readString(buf []byte) (string, []byte, bool) {
	if len(buf) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(buf[:4])
	if uint32(len(buf)-4) < n {
		return "", nil, false
	}
	return string(buf[4 : 4+n]), buf[4+n:], true
}

// demuxDockerStream parses Docker's non-TTY multiplexed stream format and
// writes stdout to channel and stderr to channel.Stderr(). Each frame is an
// 8-byte header [stream, 0,0,0, size_be32] followed by `size` payload bytes.
// stream: 1 = stdout, 2 = stderr, 0 = stdin (unused on read side).
func demuxDockerStream(channel ssh.Channel, r io.Reader) {
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header[4:8])
		if size == 0 {
			continue
		}
		var dst io.Writer = channel
		if header[0] == 2 {
			dst = channel.Stderr()
		}
		if _, err := io.CopyN(dst, r, int64(size)); err != nil {
			return
		}
	}
}
