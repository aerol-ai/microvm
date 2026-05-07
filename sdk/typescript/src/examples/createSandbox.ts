import { MicroVM } from "../index.js";

interface CLIOptions {
	apiUrl: string;
	patToken: string;
	image: string;
	cpu?: number;
	memoryMB?: number;
	diskGB?: number;
	env?: Record<string, string>;
}

async function main(): Promise<void> {
	const options = parseArgs(process.argv.slice(2));
	const client = new MicroVM({
		apiUrl: options.apiUrl,
		patToken: options.patToken,
	});

	const health = await client.health();
	console.log("health", JSON.stringify(health, null, 2));

	const sandbox = await client.create({
		image: options.image,
		cpu: options.cpu,
		memoryMB: options.memoryMB,
		diskGB: options.diskGB,
		env: options.env,
	});

	console.log("sandbox", JSON.stringify({
		id: sandbox.id,
		status: sandbox.status,
		publicURL: sandbox.publicURL,
	}, null, 2));
	console.log(`open ${sandbox.publicURL}`);
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
	const image = firstArg(args, "image") ?? "ghcr.io/aerol-ai/ubuntu:22.04";
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
	};
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