import { Client, SandboxHandle } from "./client.js";
import type { Sandbox as SandboxData } from "./types.js";

export class Sandbox extends SandboxHandle {
  constructor(client: Client, sandbox: SandboxData) {
    super(client, sandbox);
  }
}