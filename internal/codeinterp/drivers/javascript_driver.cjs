'use strict';
// AerolVM code interpreter driver for JavaScript and TypeScript (Node.js).
//
// One process is one context. It speaks the frame protocol in
// internal/codeinterp/doc.go, "fd" mode only (toolboxd). The language is
// argv[2]: "javascript" or "typescript". Node.js standard library only.
//
// Cells run as scripts in the main context, so top-level let, const, class
// and function declarations stay for the next run. Top-level await uses the
// transform of Node's own REPL (internal/repl/await, which is why node runs
// with --expose-internals): it wraps the cell in an async function and
// hoists its declarations out of it. The REPL server itself is not used: it
// routes every error, including ones from timers of earlier cells, to one
// domain, so a run could end with another run's error.
//
// Written for AerolVM (MIT). No code is taken from Daytona or E2B.

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const url = require('node:url');
const util = require('node:util');
const vm = require('node:vm');
const Module = require('node:module');
const { Writable } = require('node:stream');

const PROTOCOL_VERSION = '1';
const US = '\x1f';
const CELL = '<cell>';
const DRIVER_FILE = __filename;
// The host refuses frames over 32 MiB (codeinterp.MaxFramePayload).
const MAX_RESULT = 16 << 20;
const MAX_ERROR = 1 << 20;

const language = process.argv[2] === 'typescript' ? 'typescript' : 'javascript';
const mode = process.env.AEROL_INTERP_MODE;
const nonce = process.env.AEROL_INTERP_NONCE || '';
delete process.env.AEROL_INTERP_MODE;
delete process.env.AEROL_INTERP_NONCE;
// The cell sees a plain "node" argv, as in the REPL.
process.argv.splice(1);

let reqFd = -1;
let evFd = -1;
let outFd = 1;
let errFd = 2;
let seq = 0;
let count = 0;
// Set while a run awaits: ends that await early on SIGINT.
let interruptRun = null;

const INTERRUPTED = Symbol('interrupted');

// ------------------------------------------------------------------ frames

// reopen returns a close-on-exec copy of fd (libuv opens with O_CLOEXEC)
// and closes fd, so processes the user's code starts do not hold the
// protocol pipes open. Without /dev/fd it keeps fd.
function reopen(fd, flags) {
  try {
    const copy = fs.openSync('/dev/fd/' + fd, flags);
    if (fd > 2) fs.closeSync(fd);
    return copy;
  } catch (err) {
    return fd;
  }
}

// sleepMs blocks the thread: the driver's writes are synchronous so frames
// and markers never interleave with anything else.
const sleepCell = new Int32Array(new SharedArrayBuffer(4));
function sleepMs(ms) {
  Atomics.wait(sleepCell, 0, 0, ms);
}

function writeAll(fd, buf) {
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(fd, buf, off, buf.length - off);
    } catch (err) {
      // A pipe the user's code made non-blocking.
      if (err.code !== 'EAGAIN') throw err;
      sleepMs(1);
    }
  }
}

function emit(kind, payload) {
  const body = Buffer.from(payload, 'utf8');
  writeAll(evFd, Buffer.concat([Buffer.from(kind + ' ' + body.length + '\n', 'ascii'), body]));
}

// flushStream resolves once everything written to stream before it is out:
// Node may queue writes to a pipe. The prototype's write is used because
// user code may have replaced the stream's own.
function flushStream(stream) {
  return new Promise((resolve) => {
    if (!stream || stream.destroyed || stream.writableEnded) {
      resolve();
      return;
    }
    try {
      Writable.prototype.write.call(stream, '', () => resolve());
    } catch (err) {
      resolve();
    }
  });
}

// sync orders the user's output before the next frame (doc.go).
async function sync() {
  await Promise.all([flushStream(process.stdout), flushStream(process.stderr)]);
  seq += 1;
  const mark = Buffer.from('\x1e' + nonce + ':' + seq + '\x1e', 'utf8');
  for (const fd of [outFd, errFd]) {
    try {
      writeAll(fd, mark);
    } catch (err) {
      // The user closed it; the host then sees the pipe end instead.
    }
  }
  emit('SYNC', String(seq));
}

// Requests reads frames from the request pipe.
class Requests {
  constructor(fd) {
    this.chunks = [];
    this.length = 0;
    this.ended = false;
    this.waiter = null;
    let stream;
    try {
      stream = new net.Socket({ fd, readable: true, writable: false });
    } catch (err) {
      stream = fs.createReadStream(null, { fd });
    }
    stream.on('data', (chunk) => {
      this.chunks.push(chunk);
      this.length += chunk.length;
      this.wake();
    });
    const end = () => {
      this.ended = true;
      this.wake();
    };
    stream.on('end', end);
    stream.on('close', end);
    stream.on('error', end);
  }

  wake() {
    const w = this.waiter;
    this.waiter = null;
    if (w) w();
  }

  take(n) {
    const all = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks, this.length);
    const out = all.subarray(0, n);
    const rest = all.subarray(n);
    this.chunks = rest.length ? [rest] : [];
    this.length = rest.length;
    return out;
  }

  peekHeader() {
    const all = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks, this.length);
    this.chunks = all.length ? [all] : [];
    const nl = all.indexOf(10);
    return nl < 0 ? null : nl;
  }

  // next resolves to {kind, payload} or null at the end of the stream (or
  // on a frame the driver cannot parse, which only a broken host sends).
  async next() {
    let nl;
    while ((nl = this.peekHeader()) === null) {
      if (this.ended) return null;
      await new Promise((resolve) => { this.waiter = resolve; });
    }
    const header = this.take(nl + 1).toString('ascii').slice(0, -1);
    const sp = header.indexOf(' ');
    const n = Number(header.slice(sp + 1));
    if (sp <= 0 || !Number.isSafeInteger(n) || n < 0) return null;
    while (this.length < n) {
      if (this.ended) return null;
      await new Promise((resolve) => { this.waiter = resolve; });
    }
    return { kind: header.slice(0, sp), payload: n ? Buffer.from(this.take(n)) : Buffer.alloc(0) };
  }
}

// ---------------------------------------------------------------- compiling

let processTopLevelAwait = null;
try {
  ({ processTopLevelAwait } = require('internal/repl/await'));
} catch (err) {
  // A Node.js without the module: top-level await then needs no
  // declarations to survive (see wrapAwait).
}

let stripTypeScriptTypes = null;

// stripTypes turns a TypeScript cell into JavaScript. Strip mode first: it
// only blanks types out, so line and column numbers in errors stay right.
// Enums and namespaces need code, which only transform mode writes.
function stripTypes(code) {
  try {
    return stripTypeScriptTypes(code, { mode: 'strip' });
  } catch (err) {
    if (err && err.code === 'ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX') {
      return stripTypeScriptTypes(code, { mode: 'transform', sourceMap: false });
    }
    throw err;
  }
}

const IDENT = '[A-Za-z_$][\\w$]*';
// A static import at the start of a line. Scripts cannot use import
// statements, so they become dynamic imports; "var" lets a cell that
// imports run twice.
const IMPORT_FROM = new RegExp(
  '^([ \\t]*)import\\s+(?:(' + IDENT + ')\\s*(?:,\\s*)?)?(\\*\\s*as\\s+' + IDENT + '|\\{[^}]*\\})?\\s*' +
  'from\\s*([\'"])([^\'"\\n]+)\\4[ \\t]*;?', 'gm');
const IMPORT_BARE = /^([ \t]*)import\s*(['"])([^'"\n]+)\2[ \t]*;?/gm;

function transformImports(code) {
  if (!code.includes('import')) return code;
  code = code.replace(IMPORT_FROM, (match, indent, def, spec, quote, mod) => {
    const src = JSON.stringify(mod);
    // The replacement keeps the import's line breaks, so later lines keep
    // their numbers in errors.
    const breaks = '\n'.repeat((match.match(/\n/g) || []).length);
    if (!def && !spec) return match;
    if (spec && spec[0] === '*') {
      const ns = spec.replace(/^\*\s*as\s+/, '');
      return indent + 'var ' + ns + ' = await import(' + src + ');' +
        (def ? ' var ' + def + ' = ' + ns + '.default;' : '') + breaks;
    }
    const names = [];
    if (def) names.push('default: ' + def);
    if (spec) {
      for (const item of spec.slice(1, -1).split(',')) {
        const m = item.trim().match(/^(\S+)\s+as\s+(\S+)$/);
        if (m) names.push(m[1] + ': ' + m[2]);
        else if (item.trim()) names.push(item.trim());
      }
    }
    return indent + 'var { ' + names.join(', ') + ' } = await import(' + src + ');' + breaks;
  });
  return code.replace(IMPORT_BARE, (match, indent, quote, mod) => indent + 'await import(' + JSON.stringify(mod) + ');');
}

// Dynamic import() in a cell: Node's default loader where vm offers it
// (Node 20.12+), else an import from this file with relative and package
// names resolved against the cwd, which is what the user means.
const importModuleDynamically = (vm.constants && vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER) ||
  ((specifier) => import(resolveFromCwd(specifier)));

function resolveFromCwd(specifier) {
  if (/^\.{0,2}\//.test(specifier)) return url.pathToFileURL(path.resolve(process.cwd(), specifier)).href;
  if (/^[a-z][a-z0-9+.-]*:/i.test(specifier) || Module.isBuiltin?.(specifier)) return specifier;
  try {
    return url.pathToFileURL(Module.createRequire(path.join(process.cwd(), CELL)).resolve(specifier)).href;
  } catch (err) {
    return specifier;
  }
}

// wrapAwait returns the cell rewritten for top-level await, or null when
// it needs none.
function wrapAwait(code) {
  if (!code.includes('await')) return null;
  if (processTopLevelAwait) {
    try {
      return processTopLevelAwait(code);
    } catch (err) {
      // Not valid code: compiling it unchanged gives V8's own error.
      return null;
    }
  }
  return '(async () => { ' + code + '\n})()';
}

function compile(code) {
  return new vm.Script(code, { filename: CELL, importModuleDynamically });
}

function isThenable(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function') &&
    typeof value.then === 'function';
}

// awaitRun waits for value; SIGINT ends the wait (the work goes on in the
// background: a promise cannot be cancelled).
function awaitRun(value) {
  return new Promise((resolve, reject) => {
    interruptRun = () => reject(INTERRUPTED);
    Promise.resolve(value).then(resolve, reject);
  }).finally(() => { interruptRun = null; });
}

async function runCell(code) {
  let src = language === 'typescript' ? stripTypes(code) : code;
  src = transformImports(src);
  const wrapped = wrapAwait(src);
  let script;
  if (wrapped !== null) {
    try {
      script = compile(wrapped);
    } catch (err) {
      script = null;
    }
  }
  // The cell compiled unchanged: no await, or the wrapped form did not
  // compile, and then this reports the error against the user's code.
  const plain = !script;
  if (plain) script = compile(src);
  let value = script.runInThisContext({ breakOnSigint: true, displayErrors: false });
  if (!plain) {
    value = await awaitRun(value);
    value = processTopLevelAwait && value ? value.value : undefined;
  }
  if (isThenable(value)) value = await awaitRun(value);
  return value;
}

// ---------------------------------------------------------------- results

function cleanStack(stack) {
  const out = [];
  for (const line of String(stack).split('\n')) {
    // The frames below the cell are the driver's.
    if (/^\s+at /.test(line) && (line.includes(DRIVER_FILE) || /\bnode:vm\b/.test(line))) break;
    out.push(line);
  }
  return out.join('\n');
}

function isErrorLike(err) {
  return err !== null && typeof err === 'object' && typeof err.stack === 'string';
}

function errorPayload(err) {
  let name = 'Error';
  let value;
  let traceback;
  if (isErrorLike(err)) {
    name = String(err.name || 'Error');
    value = String(err.message === undefined ? '' : err.message);
    traceback = cleanStack(err.stack);
  } else {
    // throw 5, throw "x": no stack, shown as the REPL shows it.
    value = util.inspect(err);
    traceback = 'Uncaught ' + value;
  }
  return name + US + value.slice(0, MAX_ERROR) + US + traceback.slice(-MAX_ERROR);
}

function inspectValue(value) {
  const text = util.inspect(value);
  return text.length > MAX_RESULT / 4 ? text.slice(0, MAX_RESULT / 8) + '\n... [truncated]' : text;
}

// ------------------------------------------------------------------- runs

function applyEnv(pairs) {
  const saved = new Map();
  for (const pair of pairs) {
    const eq = pair.indexOf('=');
    if (eq <= 0) continue;
    const name = pair.slice(0, eq);
    if (!saved.has(name)) saved.set(name, Object.prototype.hasOwnProperty.call(process.env, name) ? process.env[name] : undefined);
    process.env[name] = pair.slice(eq + 1);
  }
  return saved;
}

function restoreEnv(saved) {
  for (const [name, value] of saved) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

async function execute(code, pairs) {
  count += 1;
  const saved = applyEnv(pairs);
  emit('COUNT', String(count));
  let status = 'ok';
  try {
    const value = await runCell(code);
    if (value !== undefined) {
      const text = inspectValue(value);
      await sync();
      emit('TEXT', text);
    }
  } catch (err) {
    if (err === INTERRUPTED || (err && err.code === 'ERR_SCRIPT_EXECUTION_INTERRUPTED')) {
      status = 'interrupted';
    } else {
      status = 'error';
      let payload;
      try {
        payload = errorPayload(err);
      } catch (inner) {
        // A thrown value whose getters throw must not take the driver down.
        payload = 'Error' + US + 'unprintable thrown value' + US;
      }
      await sync();
      emit('ERROR', payload);
    }
  } finally {
    interruptRun = null;
    restoreEnv(saved);
  }
  await sync();
  emit('DONE', status);
}

async function exit(code) {
  await Promise.all([flushStream(process.stdout), flushStream(process.stderr)]);
  process.exit(code);
}

async function serve(requests) {
  let env = [];
  for (;;) {
    const frame = await requests.next();
    if (frame === null || frame.kind === 'QUIT') return exit(0);
    if (frame.kind === 'ENV') {
      env.push(frame.payload.toString('utf8'));
    } else if (frame.kind === 'EXEC') {
      const pairs = env;
      env = [];
      await execute(frame.payload.toString('utf8'), pairs);
    }
  }
}

// ------------------------------------------------------------------ setup

function fatal(message) {
  if (evFd >= 0) {
    try {
      emit('FATAL', message);
    } catch (err) {
      // Nobody to tell but stderr.
    }
  }
  process.stderr.write('aerolvm interpreter driver: ' + message + '\n');
  process.exit(1);
}

async function setup() {
  if (mode !== 'fd') {
    process.stderr.write('aerolvm interpreter driver: ' + language + ' runs only in fd mode\n');
    process.exit(1);
  }
  // Without the host's pipes, Node's own event loop sits on 3 and 4 (an
  // epoll instance first), and closing those would abort the process.
  let isPipe = false;
  try {
    const st = fs.fstatSync(3);
    isPipe = (st.isFIFO() || st.isSocket()) && fs.fstatSync(4) !== null;
  } catch (err) {
    isPipe = false;
  }
  if (!isPipe) {
    process.stderr.write('aerolvm interpreter driver: protocol descriptors 3 and 4 are not open\n');
    process.exit(1);
  }
  evFd = reopen(4, fs.constants.O_WRONLY);
  reqFd = reopen(3, fs.constants.O_RDONLY);
  // Markers go through private copies of fd 1 and 2, so they reach the
  // host's pipes even if the user's code closes process.stdout.
  outFd = reopen(1, fs.constants.O_WRONLY);
  errFd = reopen(2, fs.constants.O_WRONLY);

  // The warm-ups below make Node print its one-time ExperimentalWarnings
  // (stripTypeScriptTypes, the vm loader constant) now rather than in a
  // run. Printed, they still reached the first run: the host drops output
  // from before READY only if its pipe reader has read it by then, and on
  // a busy host it may not have. So Node's warning printer is detached for
  // the warm-up and put back before READY, where the user's own warnings
  // print as usual.
  const warningListeners = process.listeners('warning');
  process.removeAllListeners('warning');

  if (language === 'typescript') {
    stripTypeScriptTypes = Module.stripTypeScriptTypes;
    if (typeof stripTypeScriptTypes !== 'function') {
      fatal('typescript needs Node.js 22.13 or newer (module.stripTypeScriptTypes); this is ' + process.version);
    }
    // The first call raises an ExperimentalWarning; raise it now, while
    // nothing prints it, not in the user's first run.
    stripTypes('let warm: number = 1');
  }

  // A cell's require resolves from the context's cwd, as in the REPL.
  globalThis.require = Module.createRequire(path.join(process.cwd(), CELL));

  process.on('SIGINT', () => {
    // Between runs a stray SIGINT must not end the context (Node's
    // default) and is otherwise ignored.
    if (interruptRun) interruptRun();
  });
  // Errors from timers and promises the cells left behind: Node would
  // exit, a REPL prints them and goes on.
  process.on('uncaughtException', (err) => {
    process.stderr.write('Uncaught ' + (isErrorLike(err) ? cleanStack(err.stack) : util.inspect(err)) + '\n');
  });
  process.on('unhandledRejection', (reason) => {
    process.stderr.write('Uncaught (in promise) ' + (isErrorLike(reason) ? cleanStack(reason.stack) : util.inspect(reason)) + '\n');
  });

  // Warm the module loader up: the first dynamic import from a script
  // raises an ExperimentalWarning on some versions.
  try {
    await compile('import("node:path")').runInThisContext();
  } catch (err) {
    // Only a warm-up.
  }
  // A warning is delivered on the next tick, so by setImmediate every
  // warm-up warning has gone to no listener; then the printer comes back.
  await new Promise((resolve) => setImmediate(resolve));
  for (const listener of warningListeners) {
    process.on('warning', listener);
  }
  await Promise.all([flushStream(process.stdout), flushStream(process.stderr)]);
  return new Requests(reqFd);
}

setup().then((requests) => {
  emit('READY', PROTOCOL_VERSION);
  return serve(requests);
}).catch((err) => fatal(isErrorLike(err) ? err.stack : String(err)));
