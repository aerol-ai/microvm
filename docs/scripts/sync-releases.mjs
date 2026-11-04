#!/usr/bin/env node
// Pulls the release notes from GitHub and writes two files from them:
//   - docs/src/data/releases.json: the saved copy the Changelog page uses when
//     GitHub cannot be reached during a docs build.
//   - CHANGELOG.md at the repository root, with the same sections as the page.
// Run it after editing or publishing a release:
//
//   npm run releases:sync            (set GITHUB_TOKEN to avoid rate limits)
import { writeFile } from 'node:fs/promises'
import { changelogMarkdown, normalize } from '../src/utils/release-notes.mjs'

const repo = 'aerol-ai/microvm'
const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'aerolvm-docs' }
if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`

const all = []
for (let page = 1; page <= 10; page++) {
  const res = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=100&page=${page}`, { headers })
  if (!res.ok) throw new Error(`GitHub releases returned ${res.status}`)
  const batch = await res.json()
  all.push(...batch)
  if (batch.length < 100) break
}

// Keep only what the page reads. The pull request lists after
// "## What's Changed" are never shown, so they are not saved.
const saved = all
  .filter(r => !r.draft)
  .map(r => ({
    tag_name: r.tag_name,
    name: r.name,
    published_at: r.published_at,
    html_url: r.html_url,
    prerelease: r.prerelease,
    body: (r.body ?? '').split(/\r?\n## What's Changed/)[0],
  }))

await writeFile(new URL('../src/data/releases.json', import.meta.url), `${JSON.stringify(saved, null, 2)}\n`)
await writeFile(new URL('../../CHANGELOG.md', import.meta.url), changelogMarkdown(normalize(saved)))
console.log(`Synced ${saved.length} releases: docs/src/data/releases.json and CHANGELOG.md`)
