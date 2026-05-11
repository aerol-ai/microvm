/// <reference types="node" />

import { MicroVM } from "../index.js";

interface CLIOptions {
	apiUrl: string;
	patToken: string;
	image: string;
	cpu?: number;
	memoryMB?: number;
	diskGB?: number;
	port: number;
	workDir: string;
	startURL: string;
	runtime?: "docker" | "gvisor" | "kata";
}

type SandboxHandle = Awaited<ReturnType<MicroVM["create"]>>;

const defaultImage = "debian:bookworm";
const defaultPort = 6080;
const defaultWorkDir = "/workspace/browser-isolation";
const defaultStartURL = "https://example.com";
const keepAliveCommand = ["sh", "-lc", "trap : TERM INT; while true; do sleep 3600; done"];

async function main(): Promise<void> {
	const options = parseArgs(process.argv.slice(2));
	const client = new MicroVM({
		apiUrl: options.apiUrl,
		patToken: options.patToken,
	});

	const sandbox = await client.create({
		image: options.image,
		cpu: options.cpu,
		memoryMB: options.memoryMB,
		diskGB: options.diskGB,
		osUser: "root",
		containerCommand: keepAliveCommand,
		runtime: options.runtime,
	});

	console.log("sandbox", JSON.stringify({
		id: sandbox.id,
		status: sandbox.status,
		image: sandbox.image,
		publicURL: sandbox.publicURL,
		runtime: sandbox.runtime,
	}, null, 2));

	await waitForShell(sandbox);
	await uploadBootstrapScript(sandbox, options.workDir);

	await runLoggedAction(sandbox, {
		name: "bootstrap browser isolation stack",
		command: `chmod +x ${shellQuote(`${options.workDir}/bootstrap.sh`)} && ${shellQuote(`${options.workDir}/bootstrap.sh`)}`,
		workDir: options.workDir,
		env: {
			DEBIAN_FRONTEND: "noninteractive",
		},
	});

	const exposure = await sandbox.exposePort(options.port);
	const previewURL = new URL("/vnc.html?autoconnect=1&resize=remote&reconnect=1", exposure.url).toString();

	const session = await startBrowserIsolation(sandbox, {
		workDir: options.workDir,
		port: options.port,
		previewURL,
		startURL: options.startURL,
	});

	console.log("browserIsolation", JSON.stringify({
		sandboxID: sandbox.id,
		sessionID: session.id,
		port: options.port,
		previewURL,
		startURL: options.startURL,
	}, null, 2));
	console.log(`open ${previewURL}`);
}

function parseArgs(argv: string[]): CLIOptions {
	const args = new Map<string, string[]>();
	for (let i = 0; i < argv.length; i += 1) {
		const token = argv[i];
		if (!token.startsWith("--")) {
			throw new Error(`unexpected argument: ${token}`);
		}
		const name = token.slice(2);
		const value = argv[i + 1];
		if (value === undefined || value.startsWith("--")) {
			throw new Error(`missing value for --${name}`);
		}
		const values = args.get(name) ?? [];
		values.push(value);
		args.set(name, values);
		i += 1;
	}

	const apiUrl = firstArg(args, "api-url") ?? process.env.SB_API_URL ?? "http://127.0.0.1:21212";
	const patToken = firstArg(args, "pat-token") ?? process.env.SB_PAT_TOKEN ?? "";
	const image = firstArg(args, "image") ?? defaultImage;
	const runtime = parseRuntime(firstArg(args, "runtime"));
	if (patToken === "") {
		throw new Error("PAT token is required. Pass --pat-token or set SB_PAT_TOKEN.");
	}

	return {
		apiUrl,
		patToken,
		image,
		cpu: parseNumber(firstArg(args, "cpu"), "cpu"),
		memoryMB: parseNumber(firstArg(args, "memory-mb"), "memory-mb"),
		diskGB: parseNumber(firstArg(args, "disk-gb"), "disk-gb"),
		port: parsePort(firstArg(args, "port")),
		workDir: firstArg(args, "work-dir") ?? defaultWorkDir,
		startURL: firstArg(args, "start-url") ?? defaultStartURL,
		runtime,
	};
}

async function waitForShell(sandbox: SandboxHandle): Promise<void> {
	const deadline = Date.now() + 30_000;
	let lastError = "shell is not ready yet";

	while (Date.now() < deadline) {
		try {
			const result = await sandbox.exec({ command: "printf ready" });
			if (result.exitCode === 0 && result.stdout === "ready") {
				return;
			}
			lastError = result.stderr || result.stdout || `command exited with code ${result.exitCode}`;
		} catch (error: unknown) {
			lastError = error instanceof Error ? error.message : String(error);
		}

		await delay(1_000);
	}

	throw new Error(`sandbox shell did not become ready in time: ${lastError}`);
}

async function uploadBootstrapScript(sandbox: SandboxHandle, workDir: string): Promise<void> {
	await sandbox.exec({ command: `mkdir -p ${shellQuote(workDir)}` });
	await sandbox.uploadFile(`${workDir}/bootstrap.sh`, buildBootstrapScript(workDir));

	console.log("files", JSON.stringify({
		workDir,
		files: [`${workDir}/bootstrap.sh`],
	}, null, 2));
}

function buildBootstrapScript(workDir: string): string {
	const runScriptPath = `${workDir}/run-browser-isolation.sh`;
	return [
		"#!/bin/sh",
		"set -eu",
		"export DEBIAN_FRONTEND=noninteractive",
		"apt-get update",
		"apt-get install -y --no-install-recommends \\",
		"  ca-certificates \\",
		"  chromium \\",
		"  novnc \\",
		"  openbox \\",
		"  websockify \\",
		"  x11-utils \\",
		"  x11vnc \\",
		"  xvfb",
		`mkdir -p ${shellQuote(workDir)}/logs ${shellQuote(workDir)}/profile`,
		`cat > ${shellQuote(runScriptPath)} <<'EOF'`,
		buildRunScript(workDir),
		"EOF",
		`chmod +x ${shellQuote(runScriptPath)}`,
		"echo 'browser isolation bootstrap complete'",
		"",
	].join("\n");
}

function buildRunScript(workDir: string): string {
	return [
		"#!/bin/sh",
		"set -eu",
		`WORKDIR=${shellQuote(workDir)}`,
		"PORT=\"${NOVNC_PORT:-6080}\"",
		"DISPLAY_NUM=\"${DISPLAY_NUM:-99}\"",
		"SCREEN_GEOMETRY=\"${SCREEN_GEOMETRY:-1440x900x24}\"",
		"WINDOW_SIZE=\"${WINDOW_SIZE:-1440,900}\"",
		"START_URL=\"${START_URL:-about:blank}\"",
		"export DISPLAY=\":${DISPLAY_NUM}\"",
		"LOGDIR=\"${WORKDIR}/logs\"",
		"PROFILE_DIR=\"${WORKDIR}/profile\"",
		"mkdir -p \"${LOGDIR}\" \"${PROFILE_DIR}\"",
		"",
		"cleanup() {",
		"  kill \"${WEBSOCKIFY_PID:-}\" \"${X11VNC_PID:-}\" \"${CHROMIUM_PID:-}\" \"${OPENBOX_PID:-}\" \"${XVFB_PID:-}\" 2>/dev/null || true",
		"}",
		"trap cleanup EXIT INT TERM",
		"",
		"Xvfb \"${DISPLAY}\" -screen 0 \"${SCREEN_GEOMETRY}\" >\"${LOGDIR}/xvfb.log\" 2>&1 &",
		"XVFB_PID=$!",
		"",
		"for _ in $(seq 1 30); do",
		"  if xdpyinfo -display \"${DISPLAY}\" >/dev/null 2>&1; then",
		"    break",
		"  fi",
		"  sleep 1",
		"done",
		"",
		"if ! xdpyinfo -display \"${DISPLAY}\" >/dev/null 2>&1; then",
		"  echo 'Xvfb did not become ready in time' >&2",
		"  exit 1",
		"fi",
		"",
		"openbox >\"${LOGDIR}/openbox.log\" 2>&1 &",
		"OPENBOX_PID=$!",
		"",
		"chromium --no-sandbox --disable-dev-shm-usage --disable-gpu --user-data-dir=\"${PROFILE_DIR}\" --window-size=\"${WINDOW_SIZE}\" \"${START_URL}\" >\"${LOGDIR}/chromium.log\" 2>&1 &",
		"CHROMIUM_PID=$!",
		"",
		"x11vnc -display \"${DISPLAY}\" -forever -shared -nopw -rfbport 5900 -listen 0.0.0.0 >\"${LOGDIR}/x11vnc.log\" 2>&1 &",
		"X11VNC_PID=$!",
		"",
		"echo \"noVNC listening on http://0.0.0.0:${PORT}/vnc.html\"",
		"websockify --web=/usr/share/novnc/ 0.0.0.0:\"${PORT}\" localhost:5900 >\"${LOGDIR}/websockify.log\" 2>&1 &",
		"WEBSOCKIFY_PID=$!",
		"wait \"${WEBSOCKIFY_PID}\"",
		"",
	].join("\n");
}

async function runLoggedAction(
	sandbox: SandboxHandle,
	action: { name: string; command: string; workDir: string; env?: Record<string, string> },
): Promise<{ stdout: string; stderr: string }> {
	const stdoutLines: string[] = [];
	const stderrLines: string[] = [];
	const stdoutLogger = createLineLogger(`[${action.name}:stdout]`, (line) => {
		stdoutLines.push(line);
	});
	const stderrLogger = createLineLogger(`[${action.name}:stderr]`, (line) => {
		stderrLines.push(line);
	});

	console.log("action:start", JSON.stringify({
		name: action.name,
		command: action.command,
		workDir: action.workDir,
	}, null, 2));

	const handle = sandbox.execStream({
		command: action.command,
		workdir: action.workDir,
		env: action.env,
		onStdout: (chunk) => stdoutLogger.write(chunk),
		onStderr: (chunk) => stderrLogger.write(chunk),
		onError: (message) => {
			console.error(`[${action.name}:error] ${message}`);
		},
	});

	const exit = await handle.done;
	stdoutLogger.flush();
	stderrLogger.flush();

	console.log("action:done", JSON.stringify({
		name: action.name,
		exit,
	}, null, 2));

	if (exit.code !== 0) {
		throw new Error(`${action.name} failed with exit code ${exit.code}`);
	}

	return {
		stdout: stdoutLines.join("\n"),
		stderr: stderrLines.join("\n"),
	};
}

async function startBrowserIsolation(
	sandbox: SandboxHandle,
	options: { workDir: string; port: number; previewURL: string; startURL: string },
): Promise<{ id: string }> {
	const actionName = "start browser isolation";
	const stdoutLines: string[] = [];
	const stderrLines: string[] = [];
	let ready = false;
	let resolveReady: (() => void) | undefined;
	let rejectReady: ((error: Error) => void) | undefined;
	const readyPromise = new Promise<void>((resolve, reject) => {
		resolveReady = resolve;
		rejectReady = reject;
	});
	const markReady = () => {
		if (ready) {
			return;
		}
		ready = true;
		resolveReady?.();
	};
	const stdoutLogger = createLineLogger(`[${actionName}:stdout]`, (line) => {
		stdoutLines.push(line);
		if (line.includes(`/vnc.html`) || line.includes(`0.0.0.0:${options.port}`)) {
			markReady();
		}
	});
	const stderrLogger = createLineLogger(`[${actionName}:stderr]`, (line) => {
		stderrLines.push(line);
	});

	console.log("action:start", JSON.stringify({
		name: actionName,
		command: "./run-browser-isolation.sh",
		workDir: options.workDir,
		previewURL: options.previewURL,
		startURL: options.startURL,
	}, null, 2));

	const session = await sandbox.createSession({
		name: `browser-isolation-${options.port}`,
		command: "./run-browser-isolation.sh",
		workDir: options.workDir,
		env: {
			NOVNC_PORT: String(options.port),
			START_URL: options.startURL,
		},
	});

	const handle = sandbox.attachSession(session.id, {
		onStdout: (chunk) => stdoutLogger.write(chunk),
		onStderr: (chunk) => stderrLogger.write(chunk),
		onError: (message) => {
			console.error(`[${actionName}:error] ${message}`);
			if (!ready) {
				rejectReady?.(new Error(message));
			}
		},
	});

	let detached = false;
	void handle.done.then((exit) => {
		if (!ready) {
			rejectReady?.(new Error(`${actionName} exited before it became ready (${formatExecExit(exit)})`));
		}
	}).catch((error: unknown) => {
		if (!detached && !ready) {
			rejectReady?.(error instanceof Error ? error : new Error(String(error)));
		}
	});

	try {
		await Promise.race([
			readyPromise,
			waitForHTTP(options.previewURL, 60_000).then(() => {
				markReady();
			}),
			timeoutAfter(60_000, `timed out waiting for noVNC to listen on port ${options.port}`),
		]);

		const previewResponse = await waitForHTTP(options.previewURL, 30_000);
		console.log("preview", JSON.stringify(await readResponseBody(previewResponse), null, 2));
		console.log("action:done", JSON.stringify({
			name: actionName,
			status: "ready",
			previewURL: options.previewURL,
			sessionID: session.id,
			stdout: stdoutLines,
			stderr: stderrLines,
		}, null, 2));
	} catch (error: unknown) {
		try {
			await sandbox.deleteSession(session.id);
		} catch {
			// Best-effort cleanup. The startup error is more useful.
		}
		throw error;
	} finally {
		detached = true;
		try {
			handle.close();
		} catch {
			// The attach stream may already be closed if startup failed early.
		}
		stdoutLogger.flush();
		stderrLogger.flush();
	}

	return { id: session.id };
}

function createLineLogger(prefix: string, onLine: (line: string) => void): {
	write(chunk: Uint8Array): void;
	flush(): void;
} {
	const decoder = new TextDecoder();
	let buffer = "";
	const emitLine = (line: string) => {
		console.log(`${prefix} ${line}`);
		onLine(line);
	};

	return {
		write(chunk: Uint8Array) {
			buffer += decoder.decode(chunk, { stream: true });
			let newlineIndex = buffer.indexOf("\n");
			while (newlineIndex >= 0) {
				emitLine(buffer.slice(0, newlineIndex).replace(/\r$/, ""));
				buffer = buffer.slice(newlineIndex + 1);
				newlineIndex = buffer.indexOf("\n");
			}
		},
		flush() {
			buffer += decoder.decode();
			if (buffer !== "") {
				emitLine(buffer.replace(/\r$/, ""));
				buffer = "";
			}
		},
	};
}

async function waitForHTTP(url: string, timeoutMS: number): Promise<Response> {
	const deadline = Date.now() + timeoutMS;
	let lastError = "request did not succeed";

	while (Date.now() < deadline) {
		try {
			const response = await fetch(url);
			if (response.ok) {
				return response;
			}
			lastError = `HTTP ${response.status}`;
		} catch (error: unknown) {
			lastError = error instanceof Error ? error.message : String(error);
		}

		await delay(1_000);
	}

	throw new Error(`request to ${url} did not succeed in time: ${lastError}`);
}

async function readResponseBody(response: Response): Promise<unknown> {
	const contentType = response.headers.get("content-type") ?? "";
	const text = await response.text();
	if (contentType.includes("application/json")) {
		try {
			return JSON.parse(text);
		} catch {
			return text;
		}
	}
	return text;
}

function timeoutAfter(ms: number, message: string): Promise<never> {
	return new Promise((_, reject) => {
		setTimeout(() => {
			reject(new Error(message));
		}, ms);
	});
}

function formatExecExit(exit: { code: number; signal?: string }): string {
	if (exit.signal) {
		return `signal ${exit.signal}`;
	}
	return `exit code ${exit.code}`;
}

function delay(ms: number): Promise<void> {
	return new Promise((resolve) => {
		setTimeout(resolve, ms);
	});
}

function firstArg(args: Map<string, string[]>, key: string): string | undefined {
	const values = args.get(key);
	return values && values.length > 0 ? values[0] : undefined;
}

function parseNumber(value: string | undefined, field: string): number | undefined {
	if (value === undefined) {
		return undefined;
	}
	const parsed = Number(value);
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error(`--${field} must be a positive number`);
	}
	return parsed;
}

function parsePort(value: string | undefined): number {
	if (value === undefined) {
		return defaultPort;
	}
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
		throw new Error("--port must be an integer between 1 and 65535");
	}
	return parsed;
}

function parseRuntime(value: string | undefined): "docker" | "gvisor" | "kata" | undefined {
	if (value === undefined) {
		return "docker";
	}
	if (value === "docker" || value === "gvisor" || value === "kata") {
		return value;
	}
	throw new Error("--runtime must be one of docker, gvisor, kata");
}

function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	console.error(message);
	process.exitCode = 1;
});