// npm ci extracts bundled dependencies from the npm tarball and ignores both
// overrides and a rewritten version on those lockfile entries. Copy the
// patched packages, pinned as direct dependencies of this package, over the
// bundled copies. Fail if the lockfile does not already record those versions:
// scanners read the lockfile and never run this script.
//
// http-cache-semantics is the exception. No release after 4.2.0 exists, and
// npm ci rejects any other version on the inBundle entry because
// make-fetch-happen's ^4.1.1 still resolves to 4.2.0. The copy below is the
// local patch; osv-scanner.toml ignores GHSA-ch52-4w7c-c8xp until upstream
// publishes a fix and this pin can move to the table above.
const fs = require('fs');
const path = require('path');

const root = __dirname;
const pins = {
  'brace-expansion': '5.0.12',
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

const cacheKey = 'node_modules/npm/node_modules/http-cache-semantics';
const cacheRecorded = lock.packages?.[cacheKey]?.version;
if (cacheRecorded !== '4.2.0') {
  console.error(
    `${cacheKey} is ${cacheRecorded}, expected 4.2.0. ` +
      'npm ci only accepts that bundled version until upstream publishes a release. ' +
      'If a fixed release exists, pin it like the packages above and drop the osv-scanner ignore.',
  );
  process.exit(1);
}
copyOverBundle('http-cache-semantics', '4.2.1-aerol.1');
const patched = fs.readFileSync(
  path.join(root, 'node_modules', 'npm', 'node_modules', 'http-cache-semantics', 'index.js'),
  'utf8',
);
if (!patched.includes('_requiresRevalidation')) {
  console.error('copied http-cache-semantics is missing the GHSA-ch52-4w7c-c8xp patch');
  process.exit(1);
}
