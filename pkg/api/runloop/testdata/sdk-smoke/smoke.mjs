// Smoke test: the official Runloop TS SDK (default http2 transport) against
// the AerolVM /runloop facade. RUNLOOP_BASE_URL and RUNLOOP_API_KEY come from
// the environment.
import { RunloopSDK } from '@runloop/api-client';

const assert = (cond, msg) => {
  if (!cond) throw new Error('ASSERT: ' + msg);
};

const sdk = new RunloopSDK({ maxRetries: 1 });

const devbox = await sdk.devbox.create({ name: 'ts-smoke', metadata: { lang: 'ts' } });
const info = await devbox.getInfo();
assert(info.status === 'running', 'running after create: ' + info.status);
assert(info.name === 'ts-smoke' && info.metadata.lang === 'ts', 'name/metadata');
console.log('create ok', devbox.id);

const r = await devbox.cmd.exec('echo hello');
assert(r.exitCode === 0 && r.success, 'exit 0');
assert((await r.stdout()) === 'hello\n', 'stdout: ' + JSON.stringify(await r.stdout()));
console.log('exec ok');

const fail = await devbox.cmd.exec('exit 7');
assert(fail.exitCode === 7 && !fail.success, 'exit 7');

let streamed = '';
const cb = await devbox.cmd.exec('echo streamed', { stdout: (line) => { streamed += line; } });
assert(cb.exitCode === 0, 'callback exec exit');
assert(streamed.includes('streamed'), 'stdout callback got: ' + JSON.stringify(streamed));
console.log('exec with callbacks ok');

const many = await devbox.cmd.exec('lines 150');
const all = await many.stdout();
assert(all.split('\n').filter(Boolean).length === 150, 'full stdout via SSE: ' + all.split('\n').length);
console.log('truncated stdout via SSE ok');

const exe = await devbox.cmd.execAsync('echo later');
const done = await exe.result();
assert((await done.stdout()) === 'later\n', 'async result');
console.log('execAsync ok');

const shell = devbox.shell('main');
const s1 = await shell.exec('echo one');
assert((await s1.stdout()) === 'one\n', 'named shell');
console.log('named shell ok');

await devbox.file.write({ file_path: 'notes/a.txt', contents: 'hi "there"\n' });
const text = await devbox.file.read({ file_path: 'notes/a.txt' });
assert(text === 'hi "there"\n', 'read: ' + JSON.stringify(text));
await devbox.file.upload({ path: 'bin.dat', file: new File([new Uint8Array([1, 2, 3])], 'bin.dat') });
const dl = await devbox.file.download({ path: 'bin.dat' });
const bytes = new Uint8Array(await dl.arrayBuffer());
assert(bytes.length === 3 && bytes[2] === 3, 'download bytes');
console.log('files ok');

const snap = await devbox.snapshotDisk({ name: 'ts-snap', metadata: { k: 'v' } });
const snapInfo = await snap.getInfo();
assert(snapInfo.status === 'complete' && snapInfo.snapshot.name === 'ts-snap', 'snapshot info');
const fromSnap = await snap.createDevbox({ name: 'from-snap' });
assert((await fromSnap.getInfo()).snapshot_id === snap.id, 'devbox from snapshot');
console.log('snapshot ok');

await devbox.suspend();
assert((await devbox.getInfo()).status === 'suspended', 'suspended');
await devbox.resume();
assert((await devbox.getInfo()).status === 'running', 'resumed');
await devbox.keepAlive();
console.log('suspend/resume ok');

const listed = await sdk.devbox.list({ limit: 10 });
assert(listed.length >= 2, 'list: ' + listed.length);

await fromSnap.shutdown();
const final = await devbox.shutdown();
assert(final.status === 'shutdown', 'shutdown');
await snap.delete();
console.log('TS SMOKE PASSED');
