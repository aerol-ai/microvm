/// <reference types="node" />

import { MicroVM } from "../index.js";

async function main(): Promise<void> {
	const apiUrl = process.env.SB_API_URL ?? "https://sandbox.aerol.cloud";
	const patToken = process.env.SB_PAT_TOKEN ?? "";
	if (patToken === "") {
		throw new Error("PAT token is required. Set SB_PAT_TOKEN.");
	}

	const sandboxID = process.argv[2];

	const client = new MicroVM({ apiUrl, patToken });

	if (!sandboxID) {
		const sandboxes = await client.list();
		if (sandboxes.length === 0) {
			console.log("No sandboxes found.");
			return;
		}
		console.log(`Found ${sandboxes.length} sandbox(es):\n`);
		for (const sb of sandboxes) {
			console.log(`  id=${sb.id}  status=${sb.status}  image=${sb.image}  created=${sb.createdAt}`);
		}
		console.log("\nUsage: npx tsx src/examples/deleteSandbox.ts <sandbox-id>");
		console.log("       npx tsx src/examples/deleteSandbox.ts --all");
		return;
	}

	if (sandboxID === "--all") {
		const sandboxes = await client.list();
		if (sandboxes.length === 0) {
			console.log("No sandboxes to delete.");
			return;
		}
		console.log(`Deleting ${sandboxes.length} sandbox(es)…`);
		await Promise.all(
			sandboxes.map(async (sb) => {
				await client.destroy(sb.id);
				console.log(`  deleted ${sb.id}`);
			}),
		);
		console.log("Done.");
		return;
	}

	await client.destroy(sandboxID);
	console.log(`deleted ${sandboxID}`);
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	console.error(message);
	process.exitCode = 1;
});
