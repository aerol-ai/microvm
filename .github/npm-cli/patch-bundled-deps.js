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
//
// glob and minimatch fixed GHSA-3g3m-2fjr-6pw4 and GHSA-g3hv-75wg-m249 only
// in new majors (glob 14.0.2, minimatch 11.0.1), and the advisories cover
// every glob 13 and minimatch 10, so no pin inside npm's ^13 and ^10 clears
// them. npm ci checks each edge between bundled packages against the range
// in the lockfile, and ignores overrides for bundled nodes. So the lockfile
// entries of the bundled packages that require glob or minimatch add
// "|| ^14.0.3" or "|| ^11.0.3" to their range; their package.json files on
// disk keep the old major. npm only calls glob(), minimatch(),
// minimatch.match(), and new Minimatch().match() with .negate, which both
// majors keep. path-scurry 3.0.0 is the major glob 14 declares; it is
// patched in so the bundle matches the glob entry, not for an advisory.
const fs = require('fs');
const path = require('path');

const root = __dirname;
const bundle = path.join(root, 'node_modules', 'npm', 'node_modules');
const pins = {
  'brace-expansion': '5.0.12',
  glob: '14.0.3',
  'http-cache-semantics': '4.2.1',
  'ip-address': '10.7.5',
  minimatch: '11.0.3',
  'path-scurry': '3.0.0',
  'postcss-selector-parser': '7.1.6',
  undici: '6.29.1',
};

const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));

function fail(message) {
  console.error(message);
  process.exit(1);
}

function copyOverBundle(name, expectVersion) {
  const src = path.join(root, 'node_modules', name);
  const dest = path.join(bundle, name);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(src, dest, { recursive: true });

  const installed = JSON.parse(fs.readFileSync(path.join(dest, 'package.json'), 'utf8')).version;
  if (installed !== expectVersion) {
    fail(`copied ${name}@${installed}, expected ${expectVersion}`);
  }
}

for (const [name, version] of Object.entries(pins)) {
  const key = `node_modules/npm/node_modules/${name}`;
  const recorded = lock.packages?.[key]?.version;
  if (recorded !== version) {
    fail(
      `${key} is ${recorded}, expected ${version}. ` +
        'Bump that lockfile entry to the patched pin; npm ci will not do it.',
    );
  }
  copyOverBundle(name, version);
}

const patched = fs.readFileSync(path.join(bundle, 'http-cache-semantics', 'index.js'), 'utf8');
if (!patched.includes('_requiresRevalidation')) {
  fail('copied http-cache-semantics is missing the GHSA-ch52-4w7c-c8xp patch');
}

// minimatch 11 requires @isaacs/nonrecursive-glob-match, which the bundle
// does not have. Node finds it by walking up to this package's node_modules,
// where the lockfile pins it. Fail here if it would load from anywhere else.
const bundledMinimatch = path.join(bundle, 'minimatch');
const matcherKey = 'node_modules/@isaacs/nonrecursive-glob-match';
const matcherPkg = require.resolve('@isaacs/nonrecursive-glob-match/package.json', {
  paths: [bundledMinimatch],
});
if (matcherPkg !== path.join(root, matcherKey, 'package.json')) {
  fail(`bundled minimatch loads @isaacs/nonrecursive-glob-match from ${matcherPkg}`);
}
const matcherVersion = JSON.parse(fs.readFileSync(matcherPkg, 'utf8')).version;
if (matcherVersion !== lock.packages?.[matcherKey]?.version) {
  fail(`@isaacs/nonrecursive-glob-match is ${matcherVersion}, the lockfile records another version`);
}

// Load the copied majors through the bundle the way npm does.
const { minimatch } = require(bundledMinimatch);
const { glob } = require(path.join(bundle, 'glob'));
if (typeof glob !== 'function' || !minimatch('lib/index.js', 'lib/*.js')) {
  fail('copied glob or minimatch does not load from the npm bundle');
}
