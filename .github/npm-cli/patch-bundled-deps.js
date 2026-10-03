// npm ci extracts bundled dependencies from the npm tarball and ignores both
// overrides and a rewritten version on those lockfile entries. Copy the
// patched packages, pinned as direct dependencies of this package, over the
// bundled copies. Fail if the lockfile does not already record those versions:
// scanners read the lockfile and never run this script.
const fs = require('fs');
const path = require('path');

const root = __dirname;
const pins = {
  'brace-expansion': '5.0.12',
  'ip-address': '10.7.3',
  undici: '6.28.1',
};

const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));

for (const [name, version] of Object.entries(pins)) {
  const key = `node_modules/npm/node_modules/${name}`;
  const recorded = lock.packages?.[key]?.version;
  if (recorded !== version) {
    console.error(
      `${key} is ${recorded}, expected ${version}. ` +
        'Bump that lockfile entry to the patched pin; npm ci will not do it.',
    );
    process.exit(1);
  }

  const src = path.join(root, 'node_modules', name);
  const dest = path.join(root, 'node_modules', 'npm', 'node_modules', name);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(src, dest, { recursive: true });

  const installed = JSON.parse(fs.readFileSync(path.join(dest, 'package.json'), 'utf8')).version;
  if (installed !== version) {
    console.error(`copied ${name}@${installed}, expected ${version}`);
    process.exit(1);
  }
}
