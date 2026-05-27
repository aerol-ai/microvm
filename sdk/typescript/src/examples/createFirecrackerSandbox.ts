import { MicroVM } from "../index.js";

async function main() {
  const client = new MicroVM({
    apiUrl: process.env.SB_API_URL ?? "http://127.0.0.1:21212",
    patToken: process.env.SB_PAT_TOKEN ?? "your-pat-token",
  });

  // 1. Create a template for the Firecracker microVM.
  console.log("Creating Firecracker template...");
  let template = await client.createTemplate({
    image: "docker://ubuntu:22.04",
  });

  console.log(`Template created with ID: ${template.id}, waiting for it to be ready...`);

  // 2. Poll until the template is ready.
  while (template.status === "pending" || template.status === "building_rootfs" || template.status === "snapshotting") {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    template = await client.getTemplate(template.id);
    console.log(`Template status: ${template.status}`);
  }

  if (template.status !== "ready" && template.status !== "ready_no_snapshot") {
    throw new Error(`Template failed to build: ${template.status}`);
  }

  console.log("Template is ready. Creating Firecracker sandbox...");

  // 3. Create the sandbox using the template ID and specifying the firecracker runtime.
  const sandbox = await client.create({
    image: template.id,
    runtime: "firecracker",
    cpu: 2,
    memoryMB: 1024,
  });

  console.log(`Sandbox created successfully!`);
  console.log(`ID: ${sandbox.id}`);
  console.log(`Public URL: ${sandbox.publicURL}`);
  console.log(`Status: ${sandbox.status}`);

  // 4. Run a command inside the Firecracker sandbox.
  console.log("Executing a command in the sandbox...");
  const execResult = await sandbox.exec({ command: "uname -a" });
  console.log("Command Output:");
  console.log(execResult.stdout.trim());

  // 5. Cleanup
  console.log("Destroying the sandbox...");
  await sandbox.destroy();
  console.log("Sandbox destroyed.");

  console.log("Deleting the template...");
  await client.deleteTemplate(template.id);
  console.log("Template deleted.");
}

main().catch((err) => {
  console.error("Failed:", err);
  process.exit(1);
});
