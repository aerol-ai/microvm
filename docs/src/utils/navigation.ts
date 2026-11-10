import type { NavigationCategory } from '../content.config'

export interface NavigationItem {
  type: 'link' | 'group'
  label?: string
}

export interface NavigationLink extends NavigationItem {
  type: 'link'
  href: string
  label: string
  description?: string
  external?: boolean
  exact?: boolean
  // Links listed under this one, in a list that starts closed (the + button).
  // Anchors inside this page are not pages, so pagination and Explore More
  // skip them. Child pages (no "#") join both, right after this link.
  children?: NavigationLink[]
  // A child page that is reference rather than a step of its parent's guide.
  // It is listed under a "Reference" heading after the guide's pages, and
  // pagination and Explore More skip it, so "Next" stays on the guide.
  reference?: boolean
}

export interface NavigationGroup extends NavigationItem {
  type: 'group'
  category?: NavigationCategory
  homePageHref?: string
  entries?: NavigationEntry[]
}

export type NavigationEntry = NavigationLink | NavigationGroup

function normalizePath(value: string): string {
  if (!value) return '/'
  const normalized = value.replace(/\/$/, '')
  return normalized === '' ? '/' : normalized
}

function groupHomePageLink(entry: NavigationGroup): NavigationLink[] {
  if (!entry.homePageHref || !entry.label) {
    return []
  }

  return [{ type: 'link', href: entry.homePageHref, label: entry.label }]
}

// A child without "#" is a page of its own (the cluster guide's pages), so it
// joins pagination, the section label and Explore More right after its
// parent. A child with "#" is a section of its parent's page (SSO's
// providers), so those skip it. Reference children join only the section
// label (withReference), so a reader landing on one still sees where it sits.
function childPages(entry: NavigationLink, withReference: boolean): NavigationLink[] {
  return (entry.children || []).filter(
    child => !child.href.includes('#') && (withReference || !child.reference)
  )
}

function flattenEntries(entries: NavigationEntry[], withReference = false): NavigationLink[] {
  return entries.flatMap(entry =>
    entry.type === 'link'
      ? [entry, ...childPages(entry, withReference)]
      : [...groupHomePageLink(entry), ...flattenEntries(entry.entries || [], withReference)]
  )
}

function flattenLinks(sidebarConfig: NavigationGroup[]): NavigationLink[] {
  return sidebarConfig.flatMap(group => flattenEntries(group.entries || []))
}

export function comparePaths(path1: string, path2: string): boolean {
  return normalizePath(path1) === normalizePath(path2)
}

export function isActiveOrParentPath(
  entryPath: string,
  currentPath: string
): boolean {
  const normalizedEntry = normalizePath(entryPath)
  const normalizedCurrent = normalizePath(currentPath)

  if (normalizedEntry === normalizedCurrent) {
    return true
  }

  if (normalizedEntry === '/') {
    return normalizedCurrent === '/'
  }

  return normalizedCurrent.startsWith(`${normalizedEntry}/`)
}

export function getSidebar(
  sidebarConfig: NavigationGroup[],
  _currentPath: string
): NavigationGroup[] {
  return sidebarConfig
}

// The top-level sidebar group a page sits in, shown above the page title so a
// reader landing from search knows which part of the docs they are in.
export function getSectionLabel(
  sidebarConfig: NavigationGroup[],
  currentPath: string
): string | undefined {
  return sidebarConfig.find(group =>
    flattenEntries(group.entries || [], true).some(link => comparePaths(link.href, currentPath))
  )?.label
}

export function getPagination(
  sidebarConfig: NavigationGroup[],
  currentPath: string
): {
  prev?: { href: string; label: string }
  next?: { href: string; label: string }
} {
  const links = flattenLinks(sidebarConfig)
  const index = links.findIndex(link => comparePaths(link.href, currentPath))

  if (index === -1) {
    return {}
  }

  return {
    prev:
      index > 0 ? { href: links[index - 1].href, label: links[index - 1].label } : undefined,
    next:
      index < links.length - 1
        ? { href: links[index + 1].href, label: links[index + 1].label }
        : undefined,
  }
}

export function getExploreMoreData(
  sidebarConfig: NavigationGroup[],
  currentPath: string
) {
  return sidebarConfig
    .map(group => ({
      title: group.label || '',
      items: flattenEntries(group.entries || [])
        .filter(link => !comparePaths(link.href, currentPath))
        .map(link => ({
          title: link.label,
          subtitle: link.description || '',
          href: link.href,
        })),
    }))
    .filter(group => group.items.length > 0)
}