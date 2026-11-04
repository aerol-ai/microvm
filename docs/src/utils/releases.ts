import snapshot from '../data/releases.json'
import { GITHUB_REPO } from './githubStars'
import { normalize, type ApiRelease, type Release } from './release-notes.mjs'

export {
  dateRange,
  formatDate,
  groupByLine,
  monthTimeline,
  slugify,
  splitNotes,
  type Release,
} from './release-notes.mjs'

// The Changelog page is built from GitHub Releases, so it is current after
// every docs build without anyone editing it. If GitHub cannot be reached
// during a build (offline, rate limit), the page falls back to the copy in
// src/data/releases.json. `npm run releases:sync` refreshes that copy and the
// repository's CHANGELOG.md from the same notes.

async function fetchFromGitHub(): Promise<ApiRelease[]> {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'aerolvm-docs',
  }
  // Optional. Without a token GitHub allows 60 requests an hour per address,
  // which a shared build machine can use up.
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  const all: ApiRelease[] = []
  for (let page = 1; page <= 10; page++) {
    const res = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=100&page=${page}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    })
    if (!res.ok) throw new Error(`GitHub releases returned ${res.status}`)
    const batch = (await res.json()) as ApiRelease[]
    all.push(...batch)
    if (batch.length < 100) break
  }
  return all
}

export interface ReleaseSource {
  releases: Release[]
  source: 'github' | 'snapshot'
}

// Fetched once per build and shared, like the star count.
let releasesPromise: Promise<ReleaseSource> | undefined

export function getReleases(): Promise<ReleaseSource> {
  releasesPromise ??= fetchFromGitHub()
    .then(raw => ({ releases: normalize(raw), source: 'github' as const }))
    .catch(error => {
      console.warn(`[changelog] Using the saved release list: ${error instanceof Error ? error.message : error}`)
      return { releases: normalize(snapshot as ApiRelease[]), source: 'snapshot' as const }
    })
  return releasesPromise
}
