// Turns GitHub release notes into changelog entries. Plain JavaScript so two
// callers share it: the Changelog page (src/pages/changelog.astro, through
// src/utils/releases.ts) and the sync script that writes the repository's
// CHANGELOG.md (scripts/sync-releases.mjs). One parser keeps the
// page and the file from drifting apart.

/**
 * @typedef {object} Release
 * @property {string} tag
 * @property {string} name
 * @property {string} publishedAt
 * @property {string} url
 * @property {string} body
 * @property {boolean} prerelease
 */

/**
 * The subset of the GitHub API's release object this code reads. The saved
 * snapshot stores the same shape.
 * @typedef {object} ApiRelease
 * @property {string} tag_name
 * @property {string | null} name
 * @property {string | null} published_at
 * @property {string} html_url
 * @property {string | null} body
 * @property {boolean} [draft]
 * @property {boolean} prerelease
 */

/** @param {ApiRelease} r @returns {Release | null} */
export function fromApi(r) {
  if (r.draft || !r.published_at) return null
  return {
    tag: r.tag_name,
    name: r.name?.trim() || r.tag_name,
    publishedAt: r.published_at,
    url: r.html_url,
    body: r.body ?? '',
    prerelease: r.prerelease,
  }
}

/** @param {string} tag @returns {number[]} */
export function versionParts(tag) {
  return tag
    .replace(/^v/, '')
    .split(/[.-]/)
    .map(n => Number.parseInt(n, 10) || 0)
}

/** @param {Release} a @param {Release} b */
export function newestFirst(a, b) {
  const [x, y] = [versionParts(a.tag), versionParts(b.tag)]
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((y[i] ?? 0) !== (x[i] ?? 0)) return (y[i] ?? 0) - (x[i] ?? 0)
  }
  return b.publishedAt.localeCompare(a.publishedAt)
}

/** @param {ApiRelease[]} raw @returns {Release[]} */
export function normalize(raw) {
  return raw
    .map(fromApi)
    .filter(/** @returns {r is Release} */ r => r !== null)
    .sort(newestFirst)
}

/**
 * Release notes follow one shape: a "## Features in vX" heading, an optional
 * lead paragraph, "### Highlights", a "---" rule, detail sections, and an
 * optional "### Upgrade notes". The changelog keeps the lead, the highlights
 * and the upgrade notes. The details and the "## What's Changed" pull request
 * list stay on GitHub, one click away.
 * @param {string} body
 * @returns {{ intro: string, highlights: string, upgrade: string }}
 */
export function splitNotes(body) {
  const text = body.replace(/\r\n/g, '\n').split(/^## What's Changed/m)[0]
  const lines = text.split('\n')
  while (lines.length && !lines[0].trim()) lines.shift()
  if (lines[0]?.startsWith('## ')) lines.shift()

  /** @type {string[]} */ const intro = []
  /** @type {string[]} */ const highlights = []
  /** @type {string[]} */ const upgrade = []
  const hasHighlights = lines.some(l => l.trim() === '### Highlights')
  /** @type {'intro' | 'highlights' | 'upgrade' | 'skip'} */
  let section = hasHighlights ? 'intro' : 'highlights'

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed === '### Highlights') {
      section = 'highlights'
      continue
    }
    if (trimmed === '### Upgrade notes') {
      section = 'upgrade'
      continue
    }
    if (trimmed === '---' || trimmed.startsWith('## ') || (trimmed.startsWith('### ') && section !== 'intro')) {
      // A release without a Highlights heading has no rule before its detail
      // sections, so its sub-headings become bold lines instead of ending it.
      if (!hasHighlights && trimmed.startsWith('### ')) {
        highlights.push(`**${trimmed.slice(4)}**`)
        continue
      }
      section = 'skip'
      continue
    }
    if (section === 'intro') intro.push(line)
    else if (section === 'highlights') highlights.push(line)
    else if (section === 'upgrade') upgrade.push(line)
  }

  return {
    intro: intro.join('\n').trim(),
    highlights: highlights.join('\n').trim(),
    upgrade: upgrade.join('\n').trim(),
  }
}

/** @param {Release[]} releases newest first @returns {{ line: string, releases: Release[] }[]} */
export function groupByLine(releases) {
  /** @type {{ line: string, releases: Release[] }[]} */
  const lines = []
  for (const release of releases) {
    const [major, minor] = versionParts(release.tag)
    const line = `${major}.${minor}`
    const current = lines.at(-1)
    if (current?.line === line) current.releases.push(release)
    else lines.push({ line, releases: [release] })
  }
  return lines
}

/** @param {string} text */
export function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-')
}

/** @param {string} iso @param {Intl.DateTimeFormatOptions} [options] */
export function formatDate(iso, options = { year: 'numeric', month: 'long', day: 'numeric' }) {
  return new Date(iso).toLocaleDateString('en-US', { ...options, timeZone: 'UTC' })
}

/** @param {Release[]} inLine newest first */
export function dateRange(inLine) {
  /** @param {string} iso */
  const short = iso => formatDate(iso, { month: 'short', day: 'numeric', year: 'numeric' })
  const first = inLine[inLine.length - 1].publishedAt
  const last = inLine[0].publishedAt
  return first.slice(0, 10) === last.slice(0, 10) ? short(last) : `${short(first)} to ${short(last)}`
}

/** Mermaid source for a timeline with one row per month. @param {Release[]} releases newest first */
export function monthTimeline(releases) {
  /** @type {Map<string, Release[]>} */
  const months = new Map()
  for (const release of [...releases].reverse()) {
    const month = formatDate(release.publishedAt, { month: 'long', year: 'numeric' })
    months.set(month, [...(months.get(month) ?? []), release])
  }
  return [
    'timeline',
    '    title Releases by month',
    ...[...months].map(([month, inMonth]) => {
      const span = inMonth.length === 1 ? inMonth[0].tag : `${inMonth[0].tag} to ${inMonth[inMonth.length - 1].tag}`
      return `    ${month} : ${inMonth.length} ${inMonth.length === 1 ? 'release' : 'releases'} : ${span}`
    }),
  ].join('\n')
}

/**
 * The repository's CHANGELOG.md, with the same sections as the docs page.
 * @param {Release[]} releases newest first
 */
export function changelogMarkdown(releases) {
  const lines = groupByLine(releases)
  const out = [
    '# Changelog',
    '',
    'Every AerolVM release, newest first: its highlights, and anything to check before you upgrade. The full notes, the merged pull requests and the downloads are on [GitHub Releases](https://github.com/aerol-ai/microvm/releases).',
    '',
    `Security fixes land on the newest release line only, which is **${lines[0]?.line}** today. See [SUPPORT.md](SUPPORT.md). This project follows [Semantic Versioning](https://semver.org).`,
    '',
    '<!-- Generated from the GitHub release notes by `npm run releases:sync` in docs/. Edit the release notes on GitHub, then run it again. The docs Changelog page is built from the same notes. -->',
    '',
    '```mermaid',
    monthTimeline(releases),
    '```',
    '',
    '| Release line | Releases | Dates | Latest |',
    '|---|---|---|---|',
  ]
  /** @type {Set<string>} */
  const used = new Set()
  /** @param {string} text */
  const anchor = text => {
    const base = slugify(text)
    let slug = base
    for (let n = 1; used.has(slug); n++) slug = `${base}-${n}`
    used.add(slug)
    return slug
  }
  const sections = lines.map(({ line, releases: inLine }) => ({
    line,
    slug: anchor(`${line} release line`),
    entries: inLine.map(release => ({ release, slug: anchor(release.name) })),
  }))
  for (const section of sections) {
    const latest = section.entries[0]
    out.push(
      `| [${section.line}](#${section.slug}) | ${section.entries.length} | ${dateRange(section.entries.map(e => e.release))} | [${latest.release.tag}](#${latest.slug}) |`
    )
  }
  for (const section of sections) {
    out.push('', `## ${section.line} release line`)
    for (const { release } of section.entries) {
      const notes = splitNotes(release.body)
      out.push('', `### ${release.name}`, '')
      out.push(`*${formatDate(release.publishedAt)}*${release.prerelease ? ' · Pre-release' : ''} · [Full notes](${release.url})`)
      if (notes.intro) out.push('', notes.intro)
      if (notes.highlights) out.push('', notes.highlights)
      if (notes.upgrade) out.push('', '**Before you upgrade:**', '', notes.upgrade)
    }
  }
  return `${out.join('\n')}\n`
}
