"""AerolVM code interpreter driver for Python.

One process is one interpreter context. It speaks the frame protocol in
internal/codeinterp/doc.go. Standard library only, and it must run on
CPython 3.8+ (toolboxd, "fd" mode) and on CPython for WASI 3.12 ("stdio"
mode: no threads, no subprocess, no signals, no extra descriptors), so
everything that needs one of those is imported late and guarded.

Written for AerolVM (MIT). No code is taken from Daytona or E2B.
"""

import ast
import base64
import builtins
import io
import json
import math
import os
import sys
import traceback
import types
import warnings

CELL = "<stdin>"
US = "\x1f"
PROTOCOL_VERSION = "1"

# The host refuses frames over 32 MiB (codeinterp.MaxFramePayload) and then
# treats the kernel as dead, so the driver keeps every frame well below it.
MAX_RESULT = 16 << 20
MAX_ERROR = 1 << 20
MAX_OUTPUT_FRAME = 1 << 20

# Byte-valued MIME types travel base64-encoded, as in Jupyter.
BINARY_MIMES = ("image/png", "image/jpeg", "application/pdf")
JSON_MIMES = ("application/json", "e2b/data")
REPR_METHODS = (
    ("text/html", "_repr_html_"),
    ("text/markdown", "_repr_markdown_"),
    ("image/svg+xml", "_repr_svg_"),
    ("image/png", "_repr_png_"),
    ("image/jpeg", "_repr_jpeg_"),
    ("text/latex", "_repr_latex_"),
    ("application/json", "_repr_json_"),
    ("application/javascript", "_repr_javascript_"),
    ("application/pdf", "_repr_pdf_"),
)

CO_COROUTINE = 0x80
TOP_LEVEL_AWAIT = getattr(ast, "PyCF_ALLOW_TOP_LEVEL_AWAIT", 0)


class _State(object):
    # running: an EXEC is in progress. user: user code is on the stack, so a
    # SIGINT may raise KeyboardInterrupt right now. pending: a SIGINT came
    # while the driver itself was writing a frame; it is raised as soon as
    # control is back in user code, so a frame is never cut in half.
    running = False
    user = False
    pending = False
    count = 0
    loop = None


S = _State()


def _on_sigint(signum, frame):
    if S.user:
        raise KeyboardInterrupt
    if S.running:
        S.pending = True
    # Idle: the host only interrupts runs, and a stray SIGINT to the group
    # must not end the context and its variables.


def _to_bytes(payload):
    if isinstance(payload, bytes):
        return payload
    # backslashreplace: a lone surrogate in user text must not kill the run.
    return payload.encode("utf-8", "backslashreplace")


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BlockingIOError:
            # User code may have set O_NONBLOCK on the shared pipe.
            import select
            select.select([], [fd], [])
            continue
        view = view[n:]


class Channel(object):
    """The request and event streams, and the output markers (fd mode)."""

    def __init__(self, mode, nonce):
        self.mode = mode
        self.seq = 0
        if mode == "fd":
            # Children started by user code (os.system, !cmd) must not hold
            # the protocol pipes, or the host would never see them close.
            os.set_inheritable(3, False)
            os.set_inheritable(4, False)
            self.req = os.fdopen(3, "rb")
            self.ev = os.fdopen(4, "wb")
            # Markers go through private copies of fd 1 and 2: they reach the
            # same pipes even when user code closes or redirects fd 1 or 2.
            self.out_fd = os.dup(1)
            self.err_fd = os.dup(2)
            self.nonce = nonce.encode("ascii")
        else:
            self.req = sys.stdin.buffer
            self.ev = sys.stdout.buffer
            # _setup replaces sys.stdin and sys.stdout; a text wrapper that is
            # collected closes its buffer, which is the protocol stream.
            self.keep = (sys.stdin, sys.stdout)
            self.out_fd = self.err_fd = None
            self.nonce = b""

    def read(self):
        """Return the next request as (kind, payload), or (None, None) at EOF."""
        header = self.req.readline()
        if not header.endswith(b"\n"):
            return None, None
        kind, _, size = header[:-1].partition(b" ")
        n = int(size)
        payload = self.req.read(n) if n else b""
        if len(payload) < n:
            return None, None
        return kind.decode("ascii"), payload

    def emit(self, kind, payload):
        payload = _to_bytes(payload)
        prev = S.user
        S.user = False
        try:
            self.ev.write(("%s %d\n" % (kind, len(payload))).encode("ascii"))
            if payload:
                self.ev.write(payload)
            self.ev.flush()
        finally:
            S.user = prev
        if prev and S.pending:
            S.pending = False
            raise KeyboardInterrupt

    def sync(self):
        """Order user output before the next event.

        In fd mode the host reads fd 1 and 2 from pipes; it forwards every
        byte before the marker before it handles the frame after SYNC.
        """
        _flush_user_streams()
        if self.mode != "fd":
            return
        self.seq += 1
        seq = str(self.seq)
        mark = b"\x1e" + self.nonce + b":" + seq.encode("ascii") + b"\x1e"
        prev = S.user
        S.user = False
        try:
            _write_all(self.out_fd, mark)
            _write_all(self.err_fd, mark)
        finally:
            S.user = prev
        self.emit("SYNC", seq)


CHAN = None


class _FrameBytes(object):
    """sys.stdout.buffer in stdio mode."""

    def __init__(self, kind, text=None):
        self._kind = kind
        self._text = text

    def write(self, b):
        # Text written before these bytes must reach the host first.
        if self._text is not None:
            self._text.flush()
        b = bytes(b)
        for i in range(0, len(b), MAX_OUTPUT_FRAME):
            CHAN.emit(self._kind, b[i:i + MAX_OUTPUT_FRAME])
        return len(b)

    def flush(self):
        pass

    def writable(self):
        return True

    def isatty(self):
        return False


class _FrameText(io.TextIOBase):
    """sys.stdout / sys.stderr in stdio mode. Line buffered, like a terminal:
    print() writes its text and its newline separately, and sending each as
    its own frame split one line into two chunks for the client. Whole lines
    go out at once; a partial line waits for its newline, a flush, or the
    next event (sync flushes)."""

    encoding = "utf-8"
    errors = "backslashreplace"

    def __init__(self, kind):
        io.TextIOBase.__init__(self)
        self._kind = kind
        self._pending = []
        self._pending_len = 0
        self.buffer = _FrameBytes(kind, self)

    def writable(self):
        return True

    def isatty(self):
        return False

    def write(self, s):
        if not isinstance(s, str):
            raise TypeError("write() argument must be str, not %s" % type(s).__name__)
        if not s:
            return 0
        self._pending.append(s)
        self._pending_len += len(s)
        if "\n" in s or self._pending_len >= MAX_OUTPUT_FRAME // 4:
            data = "".join(self._pending)
            cut = data.rfind("\n") + 1
            if self._pending_len >= MAX_OUTPUT_FRAME // 4:
                cut = len(data)
            self._pending = [data[cut:]] if cut < len(data) else []
            self._pending_len = len(data) - cut
            self._emit(data[:cut])
        return len(s)

    def _emit(self, s):
        for i in range(0, len(s), MAX_OUTPUT_FRAME // 4):
            CHAN.emit(self._kind, s[i:i + MAX_OUTPUT_FRAME // 4])

    def flush(self):
        if self._pending:
            data = "".join(self._pending)
            self._pending = []
            self._pending_len = 0
            self._emit(data)


def _flush_user_streams():
    for name in ("stdout", "stderr", "__stdout__", "__stderr__"):
        stream = getattr(sys, name, None)
        try:
            if stream is not None:
                stream.flush()
        except Exception:
            pass


# ---------------------------------------------------------------- results


def _json_safe(value, depth=0):
    """Make value JSON-encodable without NaN (the host's decoder rejects it)."""
    if depth > 100:
        return str(value)
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return dict((str(k), _json_safe(v, depth + 1)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return [_json_safe(v, depth + 1) for v in value]
    # pandas Timestamp, datetime, date: ISO strings, like E2B.
    iso = getattr(value, "isoformat", None)
    if callable(iso) and not isinstance(value, type):
        try:
            return iso()
        except Exception:
            pass
    # numpy scalars.
    item = getattr(value, "item", None)
    if callable(item) and not isinstance(value, type):
        try:
            plain = item()
            if plain is not value and (plain is None or isinstance(plain, (bool, int, float, str))):
                return _json_safe(plain, depth + 1)
        except Exception:
            pass
    return str(value)


def _normalize(bundle):
    """Clean a MIME bundle from IPython or from the repr methods."""
    out = {}
    for mime, value in bundle.items():
        if not isinstance(mime, str) or value is None:
            continue
        if mime in BINARY_MIMES:
            if isinstance(value, (bytes, bytearray)):
                value = base64.b64encode(bytes(value)).decode("ascii")
            elif not isinstance(value, str):
                continue
        elif mime in JSON_MIMES or mime.endswith("+json"):
            if isinstance(value, (bytes, bytearray)):
                value = value.decode("utf-8", "replace")
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except ValueError:
                    pass
            value = _json_safe(value)
        elif isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", "replace")
        elif not isinstance(value, str):
            continue
        out[mime] = value
    return out


def _dataframe_data(obj):
    """E2B's "data" field for a pandas DataFrame. pandas is never imported
    here: an object can only be a DataFrame if the user loaded pandas."""
    pd = sys.modules.get("pandas")
    frame_type = getattr(pd, "DataFrame", None) if pd is not None else None
    if frame_type is None or not isinstance(obj, frame_type):
        return None
    try:
        return _json_safe(obj.to_dict(orient="list"))
    except Exception:
        return None


def _formatter_method(obj, name):
    # Never call repr methods on classes (IPython's rule): a class with a
    # _repr_html_ method describes its instances, not itself.
    if isinstance(obj, type):
        return None
    try:
        method = getattr(obj, name, None)
    except Exception:
        return None
    return method if callable(method) else None


def _call_formatter(method):
    try:
        value = method()
    except Exception:
        # A broken repr method should not lose the result: show why on
        # stderr, as IPython does, and keep the other formats.
        traceback.print_exc()
        return None
    if isinstance(value, tuple) and value:
        value = value[0]
    return value


def mime_bundle(obj):
    """The plain-mode MIME bundle of obj."""
    data = {}
    method = _formatter_method(obj, "_repr_mimebundle_")
    if method is not None:
        try:
            value = method(include=None, exclude=None)
        except TypeError:
            value = _call_formatter(method)
        except Exception:
            traceback.print_exc()
            value = None
        if isinstance(value, tuple) and value:
            value = value[0]
        if isinstance(value, dict):
            data.update(value)
    for mime, name in REPR_METHODS:
        if mime in data:
            continue
        method = _formatter_method(obj, name)
        if method is not None:
            value = _call_formatter(method)
            if value is not None:
                data[mime] = value
    if "text/plain" not in data:
        data["text/plain"] = repr(obj)
    frame = _dataframe_data(obj)
    if frame is not None:
        data["e2b/data"] = frame
    return _normalize(data)


def emit_result(bundle, main):
    data = _normalize(bundle)
    if not data:
        return
    payload = _encode_result(data, main)
    CHAN.sync()
    CHAN.emit("RESULT", payload)


def _encode_result(data, main):
    data = dict(data)
    while True:
        try:
            payload = json.dumps({"data": data, "main": bool(main)}, allow_nan=False, default=str)
        except ValueError:
            data = {"text/plain": str(data.get("text/plain", ""))}
            continue
        if len(payload) <= MAX_RESULT:
            return payload
        # Too big for one frame: drop the largest rich format first, and
        # cut the text last, so the caller still sees something.
        rich = [k for k in data if k != "text/plain"]
        if rich:
            del data[max(rich, key=lambda k: len(json.dumps(data[k], default=str)))]
            continue
        text = str(data.get("text/plain", ""))
        data = {"text/plain": text[:MAX_RESULT // 8] + "\n... [truncated]"}


def display(*objs, **kwargs):
    """Show values as rich results (IPython's display() for plain mode)."""
    for obj in objs:
        emit_result(mime_bundle(obj), False)


def emit_figures():
    """Turn every open matplotlib figure into a PNG result, then close them.

    Only when the user's code loaded pyplot: importing matplotlib here would
    cost a second per run and pull a library the image may not have.
    """
    plt = sys.modules.get("matplotlib.pyplot")
    if plt is None:
        return
    try:
        numbers = list(plt.get_fignums())
    except Exception:
        return
    for number in numbers:
        try:
            fig = plt.figure(number)
            buf = io.BytesIO()
            fig.savefig(buf, format="png", bbox_inches="tight")
            emit_result({"text/plain": repr(fig), "image/png": buf.getvalue()}, False)
        except Exception:
            traceback.print_exc()
    try:
        plt.close("all")
    except Exception:
        pass


# ----------------------------------------------------------------- errors

_DRIVER_FILE = None


def _user_traceback(exc):
    """The traceback of exc without the driver's frames, so it reads like a
    REPL's: it starts at the cell, or at the library code a result's repr
    called."""
    entries = []
    tb = exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_filename != _DRIVER_FILE:
            entries.append(tb)
        tb = tb.tb_next
    for i, entry in enumerate(entries):
        if entry.tb_frame.f_code.co_filename == CELL:
            entries = entries[i:]
            break
    else:
        if isinstance(exc, SyntaxError):
            # The cell did not compile: only the parser's frames are left.
            return None
    for entry, following in zip(entries, entries[1:] + [None]):
        entry.tb_next = following
    return entries[0] if entries else None


def _safe_str(value):
    try:
        return str(value)
    except Exception:
        return "<unprintable %s object>" % type(value).__name__


def emit_error(name, value, tb_text):
    payload = name + US + value[:MAX_ERROR] + US + tb_text[-MAX_ERROR:]
    CHAN.sync()
    CHAN.emit("ERROR", payload)


def emit_exception(exc):
    tb = _user_traceback(exc)
    try:
        text = "".join(traceback.format_exception(type(exc), exc, tb))
    except Exception:
        text = "%s: %s\n" % (type(exc).__name__, _safe_str(exc))
    emit_error(type(exc).__name__, _safe_str(exc), text)


# ------------------------------------------------------------ user region


def in_user(fn, *args):
    """Run fn with interrupts enabled."""
    S.user = True
    try:
        if S.pending:
            S.pending = False
            raise KeyboardInterrupt
        return fn(*args)
    finally:
        S.user = False


def _run_awaitable(value):
    import asyncio
    if S.loop is None:
        S.loop = asyncio.new_event_loop()
    return S.loop.run_until_complete(value)


def _run_code(code_obj, ns):
    value = eval(code_obj, ns)
    if code_obj.co_flags & CO_COROUTINE:
        value = _run_awaitable(value)
    return value


# ---------------------------------------------------------- shell escapes


def _shell(cmd):
    if CHAN.mode != "fd":
        raise RuntimeError("shell commands are not available in this sandbox")
    import subprocess
    _flush_user_streams()
    code = subprocess.call(cmd, shell=True)
    sys.modules["__main__"].__dict__["_exit_code"] = code


def _pip(args):
    if CHAN.mode != "fd":
        raise RuntimeError("%pip is not available in this sandbox")
    import importlib
    import shlex
    import subprocess
    _flush_user_streams()
    subprocess.call([sys.executable, "-m", "pip"] + shlex.split(args))
    # Make packages installed by this run importable in the same process.
    importlib.invalidate_caches()


def transform_escapes(code):
    """Rewrite "!cmd" and "%pip ..." lines into calls, keeping line numbers.

    Only tried after the code failed to parse: a line starting with "!" or
    "%" is never valid Python, so valid code is never rewritten.
    """
    out = []
    changed = False
    for line in code.splitlines(True):
        body = line.rstrip("\r\n")
        newline = line[len(body):]
        stripped = body.lstrip()
        indent = body[:len(body) - len(stripped)]
        if stripped.startswith("!"):
            out.append("%s__aerol_shell__(%r)%s" % (indent, stripped[1:], newline))
            changed = True
        elif stripped == "%pip" or stripped.startswith("%pip "):
            out.append("%s__aerol_pip__(%r)%s" % (indent, stripped[4:].strip(), newline))
            changed = True
        else:
            out.append(line)
    return "".join(out) if changed else None


# ---------------------------------------------------------------- runners


class PlainRunner(object):
    """Runs cells with exec, like a REPL that shows its last expression."""

    name = "plain"

    def __init__(self, ns):
        self.ns = ns
        builtins.display = display
        builtins.__aerol_shell__ = _shell
        builtins.__aerol_pip__ = _pip

    def parse(self, code):
        try:
            return ast.parse(code, CELL, "exec")
        except SyntaxError:
            alt = transform_escapes(code)
            if alt is None:
                raise
            return ast.parse(alt, CELL, "exec")

    def cell(self, code):
        tree = self.parse(code)
        body = list(tree.body)
        last = None
        # A trailing ";" hides the value, as in IPython.
        if body and isinstance(body[-1], ast.Expr) and not code.rstrip().endswith(";"):
            last = body.pop()
        if body:
            module = ast.Module(body=body, type_ignores=[])
            _run_code(compile(module, CELL, "exec", flags=TOP_LEVEL_AWAIT), self.ns)
        if last is not None:
            expr = ast.Expression(body=last.value)
            value = _run_code(compile(expr, CELL, "eval", flags=TOP_LEVEL_AWAIT), self.ns)
            if value is not None:
                self.ns["_"] = value
                emit_result(mime_bundle(value), True)

    def run(self, code, count):
        try:
            in_user(self.cell, code)
        except KeyboardInterrupt:
            return "interrupted"
        except SystemExit:
            return "ok"
        except BaseException as exc:
            emit_exception(exc)
            return "error"
        return "ok"


def ipython_runner():
    """Runs cells in IPython's InteractiveShell, in this process (no Jupyter):
    magics, !cmd and IPython's own rich display work as in a notebook."""
    from IPython.core.displayhook import DisplayHook
    from IPython.core.displaypub import DisplayPublisher
    from IPython.core.interactiveshell import InteractiveShell
    from traitlets.config import Config

    class Hook(DisplayHook):
        # The value of a cell's last expression: a main result instead of
        # an "Out[n]:" line on stdout.
        def start_displayhook(self):
            pass

        def write_output_prompt(self):
            pass

        def write_format_data(self, format_dict, md_dict=None):
            emit_result(format_dict, True)

        def finish_displayhook(self):
            pass

    class Publisher(DisplayPublisher):
        def publish(self, data, metadata=None, *args, **kwargs):
            emit_result(data, False)

        def clear_output(self, wait=False):
            pass

    class Shell(InteractiveShell):
        captured = None

        def _showtraceback(self, etype, evalue, stb):
            self.captured = (etype, evalue, stb)

    config = Config()
    # No history database under $HOME: a context is not a terminal session.
    config.HistoryManager.enabled = False
    kwargs = dict(config=config, displayhook_class=Hook, display_pub_class=Publisher)
    try:
        shell = Shell.instance(colors="NoColor", **kwargs)
    except Exception:
        Shell.clear_instance()
        shell = Shell.instance(colors="nocolor", **kwargs)
    # system_raw keeps stdout and stderr apart and runs the command in this
    # process group, so the host's interrupt and kill reach it.
    shell.system = shell.system_raw

    formatter = shell.display_formatter
    plain_format = formatter.format

    def format_with_data(obj, include=None, exclude=None):
        data, metadata = plain_format(obj, include=include, exclude=exclude)
        frame = _dataframe_data(obj)
        if frame is not None:
            data = dict(data)
            data["e2b/data"] = frame
        return data, metadata

    formatter.format = format_with_data
    return IPythonRunner(shell)


class IPythonRunner(object):
    name = "ipython"

    def __init__(self, shell):
        self.shell = shell

    def run(self, code, count):
        shell = self.shell
        shell.captured = None
        shell.execution_count = count
        try:
            result = in_user(shell.run_cell, code, True)
        except KeyboardInterrupt:
            return "interrupted"
        except SystemExit:
            return "ok"
        err = result.error_before_exec or result.error_in_exec
        if isinstance(err, KeyboardInterrupt):
            return "interrupted"
        if isinstance(err, SystemExit):
            return "ok"
        if err is None and shell.captured is None:
            return "ok"
        if shell.captured is not None:
            etype, evalue, stb = shell.captured
            name = getattr(etype, "__name__", _safe_str(etype))
            text = "\n".join(stb) if isinstance(stb, list) else _safe_str(stb)
            emit_error(name, _safe_str(evalue), text)
        else:
            emit_exception(err)
        return "error"


# ------------------------------------------------------------------- loop


def _apply_env(pairs):
    saved = {}
    for pair in pairs:
        name, _, value = pair.partition("=")
        if not name:
            continue
        if name not in saved:
            saved[name] = os.environ.get(name)
        os.environ[name] = value
    return saved


def _restore_env(saved):
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def execute(runner, code, env_pairs):
    S.count += 1
    S.running = True
    S.pending = False
    saved = _apply_env(env_pairs)
    status = "interrupted"
    try:
        CHAN.emit("COUNT", str(S.count))
        status = runner.run(code, S.count)
        try:
            in_user(emit_figures)
        except KeyboardInterrupt:
            status = "interrupted"
        except BaseException:
            traceback.print_exc()
    finally:
        S.user = False
        S.running = False
        S.pending = False
        _restore_env(saved)
    CHAN.sync()
    CHAN.emit("DONE", status)


def _exit(code):
    _flush_user_streams()
    os._exit(code)


def serve(runner):
    env_pairs = []
    while True:
        try:
            kind, payload = CHAN.read()
            if kind is None or kind == "QUIT":
                _exit(0)
            if kind == "ENV":
                env_pairs.append(payload.decode("utf-8", "surrogateescape"))
                continue
            if kind != "EXEC":
                continue
            pairs, env_pairs = env_pairs, []
            done = False
            try:
                execute(runner, payload.decode("utf-8", "surrogateescape"), pairs)
                done = True
            finally:
                if not done:
                    # An interrupt landed in the driver's own bookkeeping,
                    # outside user code. The run still ends with one DONE.
                    S.user = False
                    S.running = False
                    CHAN.sync()
                    CHAN.emit("DONE", "interrupted")
        except KeyboardInterrupt:
            S.user = False
            S.running = False
            continue


def _setup(mode):
    global CHAN, _DRIVER_FILE
    _DRIVER_FILE = _setup.__code__.co_filename
    CHAN = Channel(mode, os.environ.pop("AEROL_INTERP_NONCE", ""))

    if mode == "fd":
        for stream in (sys.stdout, sys.stderr):
            try:
                if (stream.encoding or "").lower().replace("-", "") != "utf8":
                    stream.reconfigure(encoding="utf-8")
            except Exception:
                pass
            # PYTHONUNBUFFERED (kept for the code's python children) makes
            # print() write its text and its newline as two writes, which the
            # host could read as two chunks. Line buffering sends whole lines;
            # sync() flushes a partial line before every event.
            try:
                stream.reconfigure(line_buffering=True, write_through=False)
            except Exception:
                pass
    else:
        # The real stdin and stdout carry the protocol: user code reads an
        # empty stdin and writes through frames, and the __std*__ copies are
        # replaced too, so "sys.stdout = sys.__stdout__" cannot reach the
        # event stream.
        sys.stdin = sys.__stdin__ = io.StringIO("")
        sys.stdout = sys.__stdout__ = _FrameText("OUT")
        sys.stderr = sys.__stderr__ = _FrameText("ERR")

    try:
        import signal
        signal.signal(signal.SIGINT, _on_sigint)
    except Exception:
        pass  # WASI has no signals; interrupts stop the instance there.

    # Agg's show() is a no-op that warns; figures are sent after the run.
    warnings.filterwarnings("ignore", message=".*non-interactive, and thus cannot be shown")
    warnings.filterwarnings("ignore", message=".*which is a non-GUI backend, so cannot show the figure")
    warnings.filterwarnings("ignore", message="To exit: use 'exit', 'quit', or Ctrl-D.")
    # IPython's start-up advice for terminals; it means nothing to a caller.
    warnings.filterwarnings("ignore", message="Attempting to work in a virtualenv")

    # Imports resolve against the context's cwd, as in a REPL or a notebook,
    # not against the folder that holds this script.
    if sys.path and sys.path[0] == os.path.dirname(os.path.abspath(_DRIVER_FILE)):
        sys.path[0] = ""
    else:
        sys.path.insert(0, "")
    sys.argv = [""]

    # stdio mode needs the plain runner: IPython's !cmd children would write
    # straight into the event stream (and WASI has no IPython anyway).
    if mode == "fd" and os.environ.get("AEROL_INTERP_IPYTHON", "1") != "0":
        try:
            return ipython_runner()
        except Exception:
            # Not installed, or a version this driver cannot drive: the
            # plain runner still gives a working context.
            pass

    # User code gets its own __main__ (pickle finds classes defined in a
    # cell there), not the driver's globals.
    main = types.ModuleType("__main__")
    main.__dict__["__builtins__"] = builtins
    sys.modules["__main__"] = main
    return PlainRunner(main.__dict__)


# _setup replaces sys.modules["__main__"] with the user's module; this
# reference keeps the driver's own module (whose dict the functions above
# use as globals) from being collected.
_SELF = sys.modules.get(__name__)


def main():
    mode = os.environ.pop("AEROL_INTERP_MODE", "stdio")
    try:
        runner = _setup(mode)
    except Exception as exc:
        message = "%s: %s" % (type(exc).__name__, _safe_str(exc))
        if CHAN is not None:
            try:
                CHAN.emit("FATAL", message)
            except Exception:
                pass
        sys.stderr.write("aerolvm interpreter driver: %s\n" % message)
        _exit(1)
    CHAN.emit("READY", PROTOCOL_VERSION)
    serve(runner)


if __name__ == "__main__":
    main()
