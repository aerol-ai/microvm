/// <reference types="node" />

import { MicroVM } from "../index.js";

interface CLIOptions {
	apiUrl: string;
	patToken: string;
	image: string;
	cpu?: number;
	memoryMB?: number;
	diskGB?: number;
	env?: Record<string, string>;
	port: number;
	workDir: string;
}

type SandboxHandle = Awaited<ReturnType<MicroVM["create"]>>;

const defaultImage = "node:22-bookworm";
const defaultPort = 21212;
const defaultWorkDir = "/workspace/express-demo";
const keepAliveCommand = ["sh", "-lc", "while true; do sleep 3600; done"];
const expressPackageJSON = `${JSON.stringify({
	name: "express-demo",
	private: true,
	version: "1.0.0",
	description: "Express sample bootstrapped by the Aerol MicroVM TypeScript SDK example",
	scripts: {
		start: "node server.js",
	},
	dependencies: {
		express: "^5.1.0",
	},
}, null, 2)}
`;
const expressServerJS = [
	"const express = require(\"express\");",
	"",
	"const app = express();",
	"const port = Number(process.env.PORT || 21212);",
	"",
	"app.get(\"/\", (_req, res) => {",
	"\tres.json({",
	"\t\tservice: \"express-demo\",",
	"\t\tstatus: \"ok\",",
	"\t\tport,",
	"\t\ttime: new Date().toISOString(),",
	"\t});",
	"});",
	"",
	"app.get(\"/health\", (_req, res) => {",
	"\tres.json({ status: \"ok\", port });",
	"});",
	"",
	"app.listen(port, \"0.0.0.0\", () => {",
	"\tconsole.log(`Express server listening on http://0.0.0.0:${port}`);",
	"});",
	"",
].join("\n");

async function main(): Promise<void> {
	const options = parseArgs(process.argv.slice(2));
	const client = new MicroVM({
		apiUrl: options.apiUrl,
		patToken: options.patToken,
	});

	const health = await client.health();
	console.log("health", JSON.stringify(health, null, 2));
	const resp1 = await client.reconcile();
	console.log("reconcile", JSON.stringify(resp1, null, 2));

	const sandbox = await client.create({
		image: options.image,
		cpu: options.cpu,
		memoryMB: options.memoryMB,
		diskGB: options.diskGB,
		env: options.env,
		allowPublicTraffic: true,
		containerCommand: keepAliveCommand,
	});

	console.log("sandbox", JSON.stringify({
		id: sandbox.id,
		status: sandbox.status,
		image: sandbox.image,
		publicURL: sandbox.publicURL,
		containerCommand: sandbox.containerCommand,
	}, null, 2));

	const runtimeInfo = await waitForRuntimeInfo(sandbox);
	console.log("runtime", JSON.stringify(runtimeInfo, null, 2));

	await uploadExpressApp(sandbox, options.workDir);

	const exposure = await sandbox.exposePort(options.port);
	const publicURL = exposure.url;
	console.log("port", JSON.stringify({
		port: options.port,
		publicURL,
	}, null, 2));

	await runLoggedAction(sandbox, {
		name: "install express dependencies",
		command: "npm install",
		workDir: options.workDir,
	});

	const serverLogs = await startExpressServer(sandbox, {
		workDir: options.workDir,
		port: options.port,
		publicURL,
		env: {
			...(options.env ?? {}),
			PORT: String(options.port),
		},
	});

	console.log("server", JSON.stringify({
		port: options.port,
		publicURL,
		stdout: serverLogs.stdout,
		stderr: serverLogs.stderr,
	}, null, 2));
	console.log(`open ${publicURL}`);
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

	const apiUrl = firstArg(args, "api-url") ?? process.env.SB_API_URL ?? "https://sandbox.aerol.cloud";
	const patToken = firstArg(args, "pat-token") ?? process.env.SB_PAT_TOKEN ?? "";
	const image = firstArg(args, "image") ?? defaultImage;
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
		env: parseEnvArgs(args.get("env") ?? []),
		port: parsePort(firstArg(args, "port")),
		workDir: firstArg(args, "work-dir") ?? defaultWorkDir,
	};
}

async function waitForRuntimeInfo(sandbox: SandboxHandle): Promise<{ nodeVersion: string; npmVersion: string }> {
	const deadline = Date.now() + 30_000;
	let lastError = "sandbox runtime is not ready yet";

	while (Date.now() < deadline) {
		try {
			const result = await sandbox.exec({ command: "node --version && npm --version" });
			if (result.exitCode === 0) {
				const lines = result.stdout.split(/\r?\n/).map((line) => line.trim()).filter((line) => line !== "");
				return {
					nodeVersion: lines[0] ?? "unknown",
					npmVersion: lines[1] ?? "unknown",
				};
			}
			lastError = result.stderr || result.stdout || `command exited with code ${result.exitCode}`;
		} catch (error: unknown) {
			lastError = error instanceof Error ? error.message : String(error);
		}

		await delay(1_000);
	}

	throw new Error(`sandbox runtime did not become ready in time: ${lastError}`);
}

async function uploadExpressApp(sandbox: SandboxHandle, workDir: string): Promise<void> {
	const files = [
		{ path: `${workDir}/package.json`, data: expressPackageJSON },
		{ path: `${workDir}/server.js`, data: expressServerJS },
	];

	await Promise.all(files.map((file) => sandbox.uploadFile(file.path, file.data)));

	console.log("files", JSON.stringify({
		workDir,
		files: files.map((file) => file.path),
	}, null, 2));
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

async function startExpressServer(
	sandbox: SandboxHandle,
	options: { workDir: string; port: number; publicURL: string; env: Record<string, string> },
): Promise<{ stdout: string; stderr: string }> {
	const actionName = "start express server";
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
		if (isServerReadyLine(line, options.port)) {
			markReady();
		}
	});
	const stderrLogger = createLineLogger(`[${actionName}:stderr]`, (line) => {
		stderrLines.push(line);
		if (isServerReadyLine(line, options.port)) {
			markReady();
		}
	});

	console.log("action:start", JSON.stringify({
		name: actionName,
		command: "npm start",
		workDir: options.workDir,
		publicURL: options.publicURL,
	}, null, 2));

	// Background servers should run as sessions so we can detach cleanly after
	// readiness checks instead of keeping an exec stream transport open.
	const session = await sandbox.createSession({
		name: `express-server-${options.port}`,
		command: "npm start",
		workDir: options.workDir,
		env: options.env,
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

	const healthURL = new URL("/health", options.publicURL).toString();
	const healthReady = waitForHTTP(healthURL, 30_000);

	try {
		await Promise.race([
			readyPromise,
			healthReady.then(() => {
				markReady();
			}),
			timeoutAfter(30_000, `timed out waiting for the Express server to listen on port ${options.port}`),
		]);

		const [rootResponse, healthResponse] = await Promise.all([
			waitForHTTP(options.publicURL, 30_000),
			healthReady,
		]);

		console.log("expressRoot", JSON.stringify(await readResponseBody(rootResponse), null, 2));
		console.log("expressHealth", JSON.stringify(await readResponseBody(healthResponse), null, 2));

		console.log("action:done", JSON.stringify({
			name: actionName,
			status: "ready",
			publicURL: options.publicURL,
			sessionID: session.id,
		}, null, 2));
	} catch (error: unknown) {
		try {
			await sandbox.deleteSession(session.id);
		} catch {
			// Best-effort cleanup. The original startup error is more useful.
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

	return {
		stdout: stdoutLines.join("\n"),
		stderr: stderrLines.join("\n"),
	};
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

function isServerReadyLine(line: string, port: number): boolean {
	return line.includes(`http://0.0.0.0:${port}`) || /Express server listening/i.test(line);
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

function parseEnvArgs(values: string[]): Record<string, string> | undefined {
	if (values.length === 0) {
		return undefined;
	}
	const env: Record<string, string> = {};
	for (const value of values) {
		const separator = value.indexOf("=");
		if (separator <= 0) {
			throw new Error(`--env must be KEY=VALUE, got ${value}`);
		}
		env[value.slice(0, separator)] = value.slice(separator + 1);
	}
	return env;
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	console.error(message);
	process.exitCode = 1;
});