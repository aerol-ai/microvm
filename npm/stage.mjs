// Stages the npm packages for one aerolvm release:
//
//   node npm/stage.mjs <version> <dist-dir> <out-dir>
//
// <dist-dir> holds the release's aerolvm_<goos>_<goarch>[.exe] binaries.
// <out-dir> gets one publish-ready directory per package, and order.txt
// lists them in publish order: every platform package before the launcher,
// so `npx @aerol-ai/aerolvm` never resolves a launcher whose binary package
// is not on the registry yet.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// npm's os/cpu names for each release binary. Must match the launcher's
// `${process.platform}-${process.arch}` and the optionalDependencies list.
export const PLATFORMS = [
  { goos: 'darwin', goarch: 'arm64', os: 'darwin', cpu: 'arm64' },
  { goos: 'darwin', goarch: 'amd64', os: 'darwin', cpu: 'x64' },
  { goos: 'linux', goarch: 'arm64', os: 'linux', cpu: 'arm64' },
  { goos: 'linux', goarch: 'amd64', os: 'linux', cpu: 'x64' },
  { goos: 'windows', goarch: 'arm64', os: 'win32', cpu: 'arm64' },
  { goos: 'windows', goarch: 'amd64', os: 'win32', cpu: 'x64' },
];

const VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/;

export function stage(version, distDir, outDir) {
  version = version.replace(/^v/, '');
  if (!VERSION_RE.test(version)) {
    throw new Error(`version must look like 1.2.3, got ${JSON.stringify(version)}`);
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  const launcherDir = path.join(here, 'aerolvm');
  const launcher = JSON.parse(fs.readFileSync(path.join(launcherDir, 'package.json'), 'utf8'));

  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  const order = [];

  for (const p of PLATFORMS) {
    const name = `${launcher.name}-${p.os}-${p.cpu}`;
    if (!(name in launcher.optionalDependencies)) {
      throw new Error(`${name} is missing from npm/aerolvm/package.json optionalDependencies`);
    }
    const ext = p.goos === 'windows' ? '.exe' : '';
    const src = path.join(distDir, `aerolvm_${p.goos}_${p.goarch}${ext}`);
    if (!fs.existsSync(src)) {
      throw new Error(`missing release binary ${src}`);
    }
    const dir = `aerolvm-${p.os}-${p.cpu}`;
    const pkgDir = path.join(outDir, dir);
    fs.mkdirSync(path.join(pkgDir, 'bin'), { recursive: true });
    fs.copyFileSync(src, path.join(pkgDir, 'bin', `aerolvm${ext}`));
    fs.chmodSync(path.join(pkgDir, 'bin', `aerolvm${ext}`), 0o755);
    writeJSON(path.join(pkgDir, 'package.json'), {
      name,
      version,
      description: `The ${p.os}-${p.cpu} binary for ${launcher.name}. Install ${launcher.name}, not this.`,
      license: launcher.license,
      repository: launcher.repository,
      homepage: launcher.homepage,
      os: [p.os],
      cpu: [p.cpu],
      files: ['bin'],
      preferUnplugged: true,
      publishConfig: launcher.publishConfig,
    });
    fs.writeFileSync(
      path.join(pkgDir, 'README.md'),
      `# ${name}\n\nThe ${p.os}-${p.cpu} build of aerolvm. Install [${launcher.name}](https://www.npmjs.com/package/${launcher.name}) instead; it picks this package for you.\n`,
    );
    order.push(dir);
  }
  for (const name of Object.keys(launcher.optionalDependencies)) {
    if (!PLATFORMS.some((p) => `${launcher.name}-${p.os}-${p.cpu}` === name)) {
      throw new Error(`optionalDependencies names ${name}, which has no release binary`);
    }
  }

  const mainDir = path.join(outDir, 'aerolvm');
  fs.mkdirSync(mainDir, { recursive: true });
  for (const f of launcher.files) {
    fs.copyFileSync(path.join(launcherDir, f), path.join(mainDir, f));
  }
  fs.chmodSync(path.join(mainDir, 'aerolvm.js'), 0o755);
  writeJSON(path.join(mainDir, 'package.json'), {
    ...launcher,
    version,
    optionalDependencies: Object.fromEntries(Object.keys(launcher.optionalDependencies).map((n) => [n, version])),
  });
  order.push('aerolvm');

  fs.writeFileSync(path.join(outDir, 'order.txt'), order.join('\n') + '\n');
  return order;
}

function writeJSON(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [version, distDir, outDir] = process.argv.slice(2);
  if (!version || !distDir || !outDir) {
    process.stderr.write('usage: node npm/stage.mjs <version> <dist-dir> <out-dir>\n');
    process.exit(2);
  }
  try {
    for (const dir of stage(version, distDir, outDir)) {
      process.stdout.write(`${dir}\n`);
    }
  } catch (err) {
    process.stderr.write(`stage: ${err.message}\n`);
    process.exit(1);
  }
}
