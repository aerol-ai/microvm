import { APIClient, SandboxResource } from "./internal/client.js";
import type { Sandbox as SandboxData } from "./types.js";

export class Sandbox extends SandboxResource {
  constructor(client: APIClient, sandbox: SandboxData) {
    super(client, sandbox);
  }
}