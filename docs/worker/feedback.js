// Page feedback: the "Was this page helpful?" buttons POST here, and each vote
// lands in a GitHub Discussion named after the page path ("/platform-volumes/").
// The discussion body holds the running 👍/👎 tally; a reader's note becomes a
// comment under it. Readers never sign in, so this Worker is the only writer and
// it guards the door: same-origin POSTs only, a per-visitor rate limit, and the
// page must be a real page of this site, read back from the static assets, so a
// caller cannot mint a discussion for an arbitrary title.

const MAX_BODY_BYTES = 8 * 1024
const MAX_NOTE_CHARS = 1000
const PATH_RE = /^\/[A-Za-z0-9._/-]{0,200}$/
const COUNTS_RE = /<!-- docs-feedback (\{[^}]*\}) -->/
const GITHUB_GRAPHQL = 'https://api.github.com/graphql'

// Per-isolate caches. The category listing is the lookup of record (see
// findDiscussion), so a cold isolate only pays one extra GitHub call.
let repoCache = null
const discussionIds = new Map()

export function resetCaches() {
  repoCache = null
  discussionIds.clear()
}

export async function handleFeedback(request, env, fetchFn = fetch) {
  if (request.method !== 'POST') {
    return json({ error: 'Use POST.' }, 405, { Allow: 'POST' })
  }
  const url = new URL(request.url)
  // Browsers always send Origin on a POST, so this stops another site from
  // voting through a reader's browser. It does not stop scripts; the rate
  // limit below is for those.
  if (request.headers.get('Origin') !== url.origin) {
    return json({ error: 'Wrong origin.' }, 403)
  }
  if (!env.GITHUB_TOKEN || !env.FEEDBACK_REPO || !env.FEEDBACK_CATEGORY) {
    return json({ error: 'Page feedback is not set up on this site.' }, 503)
  }
  if (env.FEEDBACK_LIMITER) {
    const key = request.headers.get('CF-Connecting-IP') || 'unknown'
    const { success } = await env.FEEDBACK_LIMITER.limit({ key })
    if (!success) return json({ error: 'Too many votes. Try again in a minute.' }, 429)
  }

  const raw = await request.text()
  if (raw.length > MAX_BODY_BYTES) return json({ error: 'Request too large.' }, 413)
  let input
  try {
    input = parseInput(JSON.parse(raw))
  } catch (err) {
    return json({ error: err instanceof InputError ? err.message : 'Send a JSON body.' }, 400)
  }

  const page = await loadPage(env, url.origin, input.page)
  if (!page) return json({ error: 'Unknown page.' }, 404)

  const gh = github(env, fetchFn)
  try {
    const id = await findOrCreateDiscussion(gh, env, page, url.origin)
    try {
      if (input.kind === 'vote') await addVote(gh, id, page, input.vote, url.origin)
      else await addNote(gh, id, input.vote, input.note)
    } catch (err) {
      // A maintainer may have deleted the discussion; forget the id so the
      // next request finds or recreates it.
      discussionIds.delete(page.path)
      throw err
    }
  } catch (err) {
    console.error('page feedback failed', page.path, err)
    return json({ error: 'Could not save your feedback. Try again later.' }, 502)
  }
  return json({ ok: true })
}

class InputError extends Error {}

export function parseInput(body) {
  if (!body || typeof body !== 'object') throw new InputError('Send a JSON object.')
  const { page, kind = 'vote', vote, note } = body
  if (typeof page !== 'string' || !PATH_RE.test(page) || page.includes('..')) {
    throw new InputError('Unknown page.')
  }
  if (vote !== 'up' && vote !== 'down') throw new InputError('vote must be "up" or "down".')
  if (kind === 'vote') return { page: withSlash(page), kind, vote }
  if (kind !== 'note') throw new InputError('kind must be "vote" or "note".')
  if (typeof note !== 'string' || !note.trim()) throw new InputError('note is empty.')
  if (note.length > MAX_NOTE_CHARS) throw new InputError(`note is over ${MAX_NOTE_CHARS} characters.`)
  return { page: withSlash(page), kind, vote, note: note.trim() }
}

function withSlash(path) {
  return path.endsWith('/') ? path : `${path}/`
}

// The page must exist in this deploy's static assets. Its title comes from the
// built HTML, never from the request.
async function loadPage(env, origin, path) {
  const res = await env.ASSETS.fetch(new Request(new URL(path, origin), { method: 'GET' }))
  if (res.status !== 200 || !(res.headers.get('Content-Type') || '').includes('text/html')) return null
  const html = await res.text()
  const match = html.match(/<title>([^<]*)<\/title>/i)
  const title = decodeEntities(match ? match[1] : path).replace(/\s*\|\s*AerolVM\s*$/, '').trim() || path
  return { path, title }
}

function decodeEntities(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&#x27;/g, "'")
    .replace(/&amp;/g, '&')
}

function github(env, fetchFn) {
  const endpoint = env.GITHUB_API_URL || GITHUB_GRAPHQL
  return async (query, variables) => {
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        'Content-Type': 'application/json',
        'User-Agent': 'aerolvm-docs-feedback',
      },
      body: JSON.stringify({ query, variables }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok || data.errors) {
      throw new Error(`GitHub ${res.status}: ${JSON.stringify(data.errors || data.message || '')}`)
    }
    return data.data
  }
}

function repoName(env) {
  const [owner, name] = env.FEEDBACK_REPO.split('/')
  return { owner, name }
}

async function repo(gh, env) {
  if (repoCache) return repoCache
  const data = await gh(
    `query($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        id
        discussionCategories(first: 50) { nodes { id name } }
      }
    }`,
    repoName(env),
  )
  const category = data.repository.discussionCategories.nodes.find(c => c.name === env.FEEDBACK_CATEGORY)
  if (!category) throw new Error(`no discussion category named "${env.FEEDBACK_CATEGORY}"`)
  repoCache = { repoId: data.repository.id, categoryId: category.id }
  return repoCache
}

async function findOrCreateDiscussion(gh, env, page, origin) {
  const cached = discussionIds.get(page.path)
  if (cached) return cached
  const { repoId, categoryId } = await repo(gh, env)

  // List the category instead of using GitHub search: the search index lags
  // new discussions by up to minutes, and a miss there would create a
  // duplicate for every vote in that window.
  let after = null
  do {
    const data = await gh(
      `query($owner: String!, $name: String!, $categoryId: ID!, $after: String) {
        repository(owner: $owner, name: $name) {
          discussions(first: 100, after: $after, categoryId: $categoryId) {
            pageInfo { hasNextPage endCursor }
            nodes { id title }
          }
        }
      }`,
      { ...repoName(env), categoryId, after },
    )
    const list = data.repository.discussions
    for (const node of list.nodes) {
      if (!discussionIds.has(node.title)) discussionIds.set(node.title, node.id)
    }
    after = list.pageInfo.hasNextPage ? list.pageInfo.endCursor : null
  } while (after && !discussionIds.has(page.path))

  const found = discussionIds.get(page.path)
  if (found) return found

  const data = await gh(
    `mutation($repositoryId: ID!, $categoryId: ID!, $title: String!, $body: String!) {
      createDiscussion(input: { repositoryId: $repositoryId, categoryId: $categoryId, title: $title, body: $body }) {
        discussion { id }
      }
    }`,
    { repositoryId: repoId, categoryId, title: page.path, body: renderBody(page, { up: 0, down: 0 }, origin) },
  )
  const id = data.createDiscussion.discussion.id
  discussionIds.set(page.path, id)
  return id
}

// GitHub has no compare-and-set on a discussion body, so two votes on the same
// page in the same instant can drop one. At docs traffic that is rare, and a
// lost vote is cheap; it is not worth a Durable Object.
async function addVote(gh, id, page, vote, origin) {
  const data = await gh(`query($id: ID!) { node(id: $id) { ... on Discussion { body } } }`, { id })
  if (!data.node) throw new Error(`discussion ${id} is gone`)
  const counts = readCounts(data.node.body)
  counts[vote] += 1
  await gh(
    `mutation($id: ID!, $body: String!) {
      updateDiscussion(input: { discussionId: $id, body: $body }) { discussion { id } }
    }`,
    { id, body: renderBody(page, counts, origin) },
  )
}

async function addNote(gh, id, vote, note) {
  await gh(
    `mutation($id: ID!, $body: String!) {
      addDiscussionComment(input: { discussionId: $id, body: $body }) { comment { id } }
    }`,
    { id, body: renderNote(vote, note) },
  )
}

export function readCounts(body) {
  const counts = { up: 0, down: 0 }
  const match = (body || '').match(COUNTS_RE)
  if (!match) return counts
  try {
    const parsed = JSON.parse(match[1])
    for (const key of ['up', 'down']) {
      if (Number.isSafeInteger(parsed[key]) && parsed[key] >= 0) counts[key] = parsed[key]
    }
  } catch {
    // A hand-edited marker: start again from zero rather than fail the vote.
  }
  return counts
}

export function renderBody(page, counts, origin) {
  return [
    `<!-- docs-feedback ${JSON.stringify(counts)} -->`,
    `Reader votes for the docs page **${escapeMarkdown(page.title)}**: ${origin}${page.path}`,
    '',
    '| 👍 Helpful | 👎 Not helpful |',
    '|:---:|:---:|',
    `| ${counts.up} | ${counts.down} |`,
    '',
    'The "Was this page helpful?" buttons on the page update this post, so edits to it are overwritten. Notes from readers appear below as comments.',
  ].join('\n')
}

// The note goes inside a code fence so GitHub renders it as plain text: no
// links, no images, and no @mentions or #references that would ping people.
export function renderNote(vote, note) {
  const longestRun = Math.max(0, ...(note.match(/`+/g) || []).map(run => run.length))
  const fence = '`'.repeat(Math.max(3, longestRun + 1))
  const heading = vote === 'up' ? '👍 A reader found this page helpful and wrote:' : '👎 A reader found this page not helpful and wrote:'
  return `${heading}\n\n${fence}text\n${note}\n${fence}`
}

function escapeMarkdown(s) {
  return s.replace(/[\\`*_{}[\]<>|#!]/g, '\\$&')
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  })
}
