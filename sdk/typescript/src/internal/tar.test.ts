import assert from "node:assert/strict";
import test from "node:test";

import { paxRecord, tarArchive } from "./tar.js";

interface Parsed {
  name: string;
  type: string;
  mode: number;
  data: string;
  linkname: string;
}

/** Reads the archive back the way a tar reader does, checking each header's checksum. */
function parse(archive: Uint8Array): Parsed[] {
  const decoder = new TextDecoder();
  const field = (block: Uint8Array, offset: number, length: number) =>
    decoder.decode(block.subarray(offset, offset + length)).replace(/\0.*$/s, "");
  const out: Parsed[] = [];
  let pax: Record<string, string> = {};
  for (let offset = 0; offset + 512 <= archive.length; ) {
    const block = archive.subarray(offset, offset + 512);
    if (block.every((b) => b === 0)) break;
    let sum = 0;
    block.forEach((b, i) => (sum += i >= 148 && i < 156 ? 0x20 : b));
    assert.equal(parseInt(field(block, 148, 8), 8), sum, "checksum");
    assert.equal(field(block, 257, 6), "ustar");
    const size = parseInt(field(block, 124, 12), 8);
    const type = field(block, 156, 1);
    const data = decoder.decode(archive.subarray(offset + 512, offset + 512 + size));
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === "x") {
      pax = {};
      for (let rest = data; rest.length > 0; ) {
        const length = parseInt(rest, 10);
        const record = rest.slice(0, length);
        assert.ok(record.endsWith("\n"), "a PAX record's length must count the whole record");
        const [key, ...value] = record.slice(record.indexOf(" ") + 1, -1).split("=");
        pax[key] = value.join("=");
        rest = rest.slice(length);
      }
      continue;
    }
    out.push({
      name: pax.path ?? field(block, 0, 100),
      type,
      mode: parseInt(field(block, 100, 8), 8),
      data,
      linkname: pax.linkpath ?? field(block, 157, 100),
    });
    pax = {};
  }
  return out;
}

test("tarArchive writes files, folders, symlinks and long names", () => {
  const long = `deep/${"x".repeat(150)}/file.txt`;
  const archive = tarArchive([
    { name: "src", type: "dir", mode: 0o755, mtime: 1700000000 },
    { name: "src/a.txt", type: "file", mode: 0o640, mtime: 1700000000, data: new TextEncoder().encode("alpha") },
    { name: "link", type: "symlink", mode: 0o777, mtime: 1700000000, linkname: "src/a.txt" },
    { name: long, type: "file", mode: 0o644, mtime: 1700000000, data: new TextEncoder().encode("y".repeat(600)) },
    { name: "far", type: "symlink", mode: 0o777, mtime: 1700000000, linkname: "t".repeat(130) },
  ]);
  assert.equal(archive.length % 512, 0);
  const entries = parse(archive);
  assert.deepEqual(
    entries.map((e) => [e.name, e.type]),
    [["src/", "5"], ["src/a.txt", "0"], ["link", "2"], [long, "0"], ["far", "2"]],
  );
  assert.equal(entries[1].data, "alpha");
  assert.equal(entries[1].mode, 0o640);
  assert.equal(entries[2].linkname, "src/a.txt");
  assert.equal(entries[3].data, "y".repeat(600));
  assert.equal(entries[4].linkname, "t".repeat(130));
});

test("a PAX record's length counts its own digits", () => {
  for (let n = 80; n < 1010; n++) {
    const record = paxRecord("path", "v".repeat(n));
    assert.equal(parseInt(new TextDecoder().decode(record), 10), record.length, `value length ${n}`);
  }
});
