// npm ci extracts bundled dependencies from the npm tarball and ignores both
// overrides and a rewritten version on those lockfile entries. Copy the
// patched packages, pinned as direct dependencies of this package, over the
// bundled copies. Fail if the lockfile does not already record those versions:
// scanners read the lockfile and never run this script.
//
// http-cache-semantics 4.2.1 is not an upstream release. Nothing after 4.2.0
// is published, and that version is the last one affected by GHSA-ch52-4w7c-c8xp.
// A prerelease does not satisfy make-fetch-happen's ^4.1.1, so npm ci rejects
// it on the inBundle entry. 4.2.1 satisfies the range and is outside the
// advisory (<= 4.2.0), so scanners reading the lockfile do not see 4.2.0.
const fs = require('fs');
const path = require('path');

const root = __dirname;
const pins = {
  'brace-expansion': '5.0.12',
  'http-cache-semantics': '4.2.1',
  'ip-address': '10.7.3',
  undici: '6.28.1',
};

const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));

function copyOverBundle(name, expectVersion) {
  const src = path.join(root, 'node_modules', name);
  const dest = path.join(root, 'node_modules', 'npm', 'node_modules', name);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(src, dest, { recursive: true });

  const installed = JSON.parse(fs.readFileSync(path.join(dest, 'package.json'), 'utf8')).version;
  if (installed !== expectVersion) {
    console.error(`copied ${name}@${installed}, expected ${expectVersion}`);
    process.exit(1);
  }
}

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
  copyOverBundle(name, version);
}

const patched = fs.readFileSync(
  path.join(root, 'node_modules', 'npm', 'node_modules', 'http-cache-semantics', 'index.js'),
  'utf8',
);
if (!patched.includes('_requiresRevalidation')) {
  console.error('copied http-cache-semantics is missing the GHSA-ch52-4w7c-c8xp patch');
  process.exit(1);
}
