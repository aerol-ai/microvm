// Run with: node --test worker/
// Uses an in-memory fake of the four GitHub GraphQL calls, so it never touches
// the real repository.
import assert from 'node:assert/strict'
import { beforeEach, test } from 'node:test'
import { handleFeedback, parseInput, readCounts, renderBody, renderNote, resetCaches } from './feedback.js'

const ORIGIN = 'https://docs.example.com'

function fakeGitHub({ categories = [{ id: 'CAT1', name: 'Docs feedback' }] } = {}) {
  const state = { discussions: [], comments: [], calls: [], fail: false }
  state.fetch = async (_url, init) => {
    const { query, variables } = JSON.parse(init.body)
    state.calls.push(query.match(/(createDiscussion|updateDiscussion|addDiscussionComment|discussionCategories|discussions\(|node\()/)[1])
    if (state.fail) return Response.json({ errors: [{ message: 'boom' }] })
    if (query.includes('discussionCategories')) {
      return Response.json({ data: { repository: { id: 'REPO1', discussionCategories: { nodes: categories } } } })
    }
    if (query.includes('createDiscussion')) {
      const d = { id: `D${state.discussions.length + 1}`, ...variables }
      state.discussions.push(d)
      return Response.json({ data: { createDiscussion: { discussion: { id: d.id } } } })
    }
    if (query.includes('updateDiscussion')) {
      state.discussions.find(d => d.id === variables.id).body = variables.body
      return Response.json({ data: { updateDiscussion: { discussion: { id: variables.id } } } })
    }
    if (query.includes('addDiscussionComment')) {
      state.comments.push(variables)
      return Response.json({ data: { addDiscussionComment: { comment: { id: 'C1' } } } })
    }
    if (query.includes('node(')) {
      const d = state.discussions.find(x => x.id === variables.id)
      return Response.json({ data: { node: d ? { body: d.body } : null } })
    }
    const nodes = state.discussions.filter(d => d.categoryId === variables.categoryId).map(d => ({ id: d.id, title: d.title }))
    return Response.json({ data: { repository: { discussions: { pageInfo: { hasNextPage: false, endCursor: null }, nodes } } } })
  }
  return state
}

function env(overrides = {}) {
  const pages = { '/platform-volumes/': 'Platform Volumes | AerolVM', '/': 'Intro &amp; Setup | AerolVM' }
  return {
    GITHUB_TOKEN: 'test-token',
    FEEDBACK_REPO: 'aerol-ai/microvm',
    FEEDBACK_CATEGORY: 'Docs feedback',
    ASSETS: {
      fetch: async req => {
        const title = pages[new URL(req.url).pathname]
        if (!title) return new Response('not found', { status: 404 })
        return new Response(`<html><head><title>${title}</title></head></html>`, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
      },
    },
    ...overrides,
  }
}

function post(body, headers = {}) {
  return new Request(`${ORIGIN}/api/feedback`, {
    method: 'POST',
    headers: { Origin: ORIGIN, 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

beforeEach(() => resetCaches())

test('first vote creates one discussion named after the page path', async () => {
  const gh = fakeGitHub()
  const res = await handleFeedback(post({ page: '/platform-volumes/', vote: 'up' }), env(), gh.fetch)
  assert.equal(res.status, 200)
  assert.equal(gh.discussions.length, 1)
  const [d] = gh.discussions
  assert.equal(d.title, '/platform-volumes/')
  assert.equal(d.categoryId, 'CAT1')
  assert.deepEqual(readCounts(d.body), { up: 1, down: 0 })
  assert.match(d.body, /\*\*Platform Volumes\*\*: https:\/\/docs\.example\.com\/platform-volumes\//)
})

test('later votes reuse the discussion and keep counting', async () => {
  const gh = fakeGitHub()
  await handleFeedback(post({ page: '/platform-volumes/', vote: 'up' }), env(), gh.fetch)
  resetCaches() // a fresh isolate must find the discussion by listing, not create another
  await handleFeedback(post({ page: '/platform-volumes', vote: 'down' }), env(), gh.fetch)
  await handleFeedback(post({ page: '/platform-volumes/', vote: 'down' }), env(), gh.fetch)
  assert.equal(gh.discussions.length, 1)
  assert.deepEqual(readCounts(gh.discussions[0].body), { up: 1, down: 2 })
})

test('a note becomes a plain-text comment and does not count as a vote', async () => {
  const gh = fakeGitHub()
  await handleFeedback(post({ page: '/platform-volumes/', vote: 'down' }), env(), gh.fetch)
  const note = 'Missing the S3 limits @someone #12 [x](https://spam.example) ```'
  const res = await handleFeedback(post({ page: '/platform-volumes/', kind: 'note', vote: 'down', note }), env(), gh.fetch)
  assert.equal(res.status, 200)
  assert.deepEqual(readCounts(gh.discussions[0].body), { up: 0, down: 1 })
  assert.equal(gh.comments.length, 1)
  assert.equal(gh.comments[0].body, renderNote('down', note))
  assert.match(gh.comments[0].body, /^👎 .*\n\n````text\n/)
})

test('rejects requests that could spam the repository', async () => {
  const gh = fakeGitHub()
  const cases = [
    [new Request(`${ORIGIN}/api/feedback`), 405],
    [post({ page: '/platform-volumes/', vote: 'up' }, { Origin: 'https://evil.example' }), 403],
    [post('not json'), 400],
    [post({ page: '/platform-volumes/', vote: 'meh' }), 400],
    [post({ page: '/../etc/', vote: 'up' }), 400],
    [post({ page: 'https://evil.example/', vote: 'up' }), 400],
    [post({ page: '/platform-volumes/', kind: 'note', vote: 'down', note: '   ' }), 400],
    [post({ page: '/platform-volumes/', kind: 'note', vote: 'down', note: 'x'.repeat(1001) }), 400],
    [post({ page: '/no-such-page/', vote: 'up' }), 404],
    [post({ page: '/platform-volumes/', vote: 'up', pad: 'x'.repeat(9000) }), 413],
  ]
  for (const [i, [req, status]] of cases.entries()) {
    const res = await handleFeedback(req, env(), gh.fetch)
    assert.equal(res.status, status, `case ${i}`)
  }
  assert.equal(gh.discussions.length, 0)
  assert.equal(gh.calls.length, 0)
})

test('rate limit and missing setup stop the request before GitHub', async () => {
  const gh = fakeGitHub()
  const limited = env({ FEEDBACK_LIMITER: { limit: async () => ({ success: false }) } })
  assert.equal((await handleFeedback(post({ page: '/', vote: 'up' }), limited, gh.fetch)).status, 429)
  assert.equal((await handleFeedback(post({ page: '/', vote: 'up' }), env({ GITHUB_TOKEN: '' }), gh.fetch)).status, 503)
  assert.equal(gh.calls.length, 0)
})

test('GitHub errors return 502, and a missing category is an error', async () => {
  const gh = fakeGitHub({ categories: [{ id: 'X', name: 'General' }] })
  assert.equal((await handleFeedback(post({ page: '/', vote: 'up' }), env(), gh.fetch)).status, 502)
  const broken = fakeGitHub()
  broken.fail = true
  assert.equal((await handleFeedback(post({ page: '/', vote: 'up' }), env(), broken.fetch)).status, 502)
})

test('page titles come from the built HTML and are escaped', () => {
  const body = renderBody({ path: '/', title: 'Intro & *Setup*' }, { up: 3, down: 1 }, ORIGIN)
  assert.match(body, /\*\*Intro & \\\*Setup\\\*\*\*/)
  assert.deepEqual(readCounts(body), { up: 3, down: 1 })
  assert.deepEqual(readCounts('<!-- docs-feedback {"up":-4,"down":"x"} -->'), { up: 0, down: 0 })
  assert.deepEqual(readCounts('hand edited, no marker'), { up: 0, down: 0 })
})

test('parseInput adds the trailing slash pages are served with', () => {
  assert.deepEqual(parseInput({ page: '/tcp-ports', vote: 'up' }), { page: '/tcp-ports/', kind: 'vote', vote: 'up' })
})
