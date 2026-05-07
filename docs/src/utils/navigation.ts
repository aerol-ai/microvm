import type { NavigationCategory } from '../content/config'

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
}

export interface NavigationGroup extends NavigationItem {
  type: 'group'
  category: NavigationCategory
  homePageHref?: string
  entries?: NavigationLink[]
}

function normalizePath(value: string): string {
  if (!value) return '/'
  const normalized = value.replace(/\/$/, '')
  return normalized === '' ? '/' : normalized
}

function flattenLinks(sidebarConfig: NavigationGroup[]): NavigationLink[] {
  return sidebarConfig.flatMap(group => group.entries || [])
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
      items: (group.entries || [])
        .filter(link => !comparePaths(link.href, currentPath))
        .map(link => ({
          title: link.label,
          subtitle: link.description || '',
          href: link.href,
        })),
    }))
    .filter(group => group.items.length > 0)
}