import { docsSchema } from '@astrojs/starlight/schema'
import { defineCollection, z } from 'astro:content'

import type { NavigationGroup } from '../utils/navigation'

export const collections = {
  docs: defineCollection({
    schema: docsSchema({
      extend: z.object({
        hideTitleOnPage: z.boolean().optional(),
      }),
    }),
  }),
}

export enum NavigationCategory {
  OVERVIEW,
  FEATURES,
}

export const getSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Overview',
    category: NavigationCategory.OVERVIEW,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/',
        label: 'Introduction',
        description: 'What this project ships and how the docs are organized.',
      },
      {
        type: 'link',
        href: '/getting-started',
        label: 'Getting Started',
        description: 'Build, configure, and run the sandbox daemon locally.',
      },
      {
        type: 'link',
        href: '/architecture',
        label: 'Architecture',
        description: 'How sandboxd, toolboxd, Docker, and storage fit together.',
      },
      {
        type: 'link',
        href: '/sdk-clients',
        label: 'SDK Clients',
        description: 'The Go, TypeScript, Python, and Rust SDK surface area.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Features',
    category: NavigationCategory.FEATURES,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/exec-streaming',
        label: 'Streaming Exec',
        description: 'Live stdout, stderr, PTY sessions, and interactive process control.',
      },
      {
        type: 'link',
        href: '/external-storage',
        label: 'External Storage',
        description: 'Mount S3, NFS, SSHFS, and rclone-backed storage into sandboxes.',
      },
      {
        type: 'link',
        href: '/network-isolation',
        label: 'Network Isolation',
        description: 'Block egress with host-level firewall rules on a per-sandbox basis.',
      },
      {
        type: 'link',
        href: '/port-allowlist',
        label: 'Port Allowlist',
        description: 'Require explicit exposure before public traffic reaches a sandbox port.',
      },
    ],
  },
]