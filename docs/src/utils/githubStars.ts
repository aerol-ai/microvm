export const GITHUB_REPO = 'aerol-ai/microvm'

// Fetched once per build and shared by every page, so a build makes one
// GitHub API call. The card also refreshes the number in the browser, so a
// failed fetch here (offline build, rate limit) only means it appears a moment
// after the page loads.
let starsPromise: Promise<number | null> | undefined

export function getStars(): Promise<number | null> {
  starsPromise ??= fetch(`https://api.github.com/repos/${GITHUB_REPO}`, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'aerolvm-docs' },
    signal: AbortSignal.timeout(5000),
  })
    .then(res => (res.ok ? res.json() : null))
    .then(data => (typeof data?.stargazers_count === 'number' ? data.stargazers_count : null))
    .catch(() => null)
  return starsPromise
}

export function formatStars(count: number): string {
  const label = count === 1 ? 'star' : 'stars'
  if (count < 1000) return `${count} ${label}`
  const thousands = (count / 1000).toFixed(count < 10000 ? 1 : 0).replace(/\.0$/, '')
  return `${thousands}k ${label}`
}
