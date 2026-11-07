// A minimal tar writer for uploadDir (plans/agent-sandbox-feature-parity.md,
// F3). Node has no tar module, and the SDK takes no dependencies. It writes
// ustar headers, with a PAX record for a name or link target longer than
// ustar's 100 bytes, which Go's archive/tar (toolboxd) reads.

const BLOCK = 512;
const encoder = new TextEncoder();

/** One archive member. Names use "/" and are relative to the folder. */
export interface TarEntry {
  name: string;
  type: "file" | "dir" | "symlink";
  mode: number;
  /** Seconds since the epoch. */
  mtime: number;
  data?: Uint8Array;
  linkname?: string;
}

function putString(block: Uint8Array, offset: number, length: number, value: string | Uint8Array): void {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  block.set(bytes.subarray(0, length), offset);
}

function putOctal(block: Uint8Array, offset: number, length: number, value: number): void {
  putString(block, offset, length - 1, Math.floor(value).toString(8).padStart(length - 1, "0"));
}

function header(name: Uint8Array, typeflag: string, mode: number, size: number, mtime: number, linkname: Uint8Array): Uint8Array {
  const block = new Uint8Array(BLOCK);
  putString(block, 0, 100, name);
  putOctal(block, 100, 8, mode & 0o7777);
  putOctal(block, 108, 8, 0);
  putOctal(block, 116, 8, 0);
  putOctal(block, 124, 12, size);
  putOctal(block, 136, 12, mtime);
  block.fill(0x20, 148, 156);
  putString(block, 156, 1, typeflag);
  putString(block, 157, 100, linkname);
  putString(block, 257, 6, "ustar\0");
  putString(block, 263, 2, "00");
  let sum = 0;
  for (const byte of block) sum += byte;
  putString(block, 148, 8, `${sum.toString(8).padStart(6, "0")}\0 `);
  return block;
}

/** A PAX record: "<length> <key>=<value>\n", the length counting itself. */
export function paxRecord(key: string, value: string): Uint8Array {
  const body = encoder.encode(` ${key}=${value}\n`);
  let length = body.length + String(body.length).length;
  if (String(length).length !== String(body.length).length) {
    // Adding the digits made the number one digit longer (98 -> 100).
    length = body.length + String(length).length;
  }
  return encoder.encode(`${length} ${key}=${value}\n`);
}

function padded(data: Uint8Array): Uint8Array[] {
  const rest = data.length % BLOCK;
  return rest === 0 ? [data] : [data, new Uint8Array(BLOCK - rest)];
}

/** The entries as one uncompressed tar archive. */
export function tarArchive(entries: TarEntry[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const entry of entries) {
    const name = encoder.encode(entry.type === "dir" && !entry.name.endsWith("/") ? `${entry.name}/` : entry.name);
    const linkname = encoder.encode(entry.linkname ?? "");
    const records: Uint8Array[] = [];
    if (name.length > 100) records.push(paxRecord("path", new TextDecoder().decode(name)));
    if (linkname.length > 100) records.push(paxRecord("linkpath", entry.linkname ?? ""));
    if (records.length > 0) {
      const pax = concat(records);
      chunks.push(header(encoder.encode("PaxHeader"), "x", 0o644, pax.length, entry.mtime, new Uint8Array()), ...padded(pax));
    }
    const data = entry.type === "file" ? entry.data ?? new Uint8Array() : new Uint8Array();
    const typeflag = entry.type === "file" ? "0" : entry.type === "dir" ? "5" : "2";
    chunks.push(header(name, typeflag, entry.mode, data.length, entry.mtime, linkname));
    if (data.length > 0) chunks.push(...padded(data));
  }
  chunks.push(new Uint8Array(BLOCK * 2));
  return concat(chunks);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
