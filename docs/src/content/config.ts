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
  SANDBOX,
  TOOLBOX,
  ACCESS,
  SDKS,
  FEATURES,
}

export const getSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Introduction',
    category: NavigationCategory.OVERVIEW,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/quick-start',
        label: 'Quick Start',
        description: 'Spin up a sandbox and run a command in under five minutes.',
      },
      {
        type: 'link',
        href: '/getting-started',
        label: 'Server Setup',
        description: 'Install and configure AerolVM on a Linux host.',
      },
      {
        type: 'link',
        href: '/sdk-setup',
        label: 'SDK Setup',
        description: 'Connect an SDK to your AerolVM server.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Sandbox',
    category: NavigationCategory.SANDBOX,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/sandboxes',
        label: 'Create Sandbox',
        description: 'Create, start, stop, destroy, and resize sandboxes.',
      },
      {
        type: 'link',
        href: '/environment',
        label: 'Environment',
        description: 'Docker image, env vars, resource limits, and idle lifecycle.',
      },
      {
        type: 'link',
        href: '/external-storage',
        label: 'Volumes',
        description: 'Mount S3, NFS, SSHFS, and rclone-backed storage into sandboxes.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Toolbox',
    category: NavigationCategory.TOOLBOX,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/file-system',
        label: 'File System',
        description: 'Upload and download files into and out of the sandbox.',
      },
      {
        type: 'link',
        href: '/exec-streaming',
        label: 'Process & Code Execution',
        description: 'Live stdout, stderr, PTY sessions, and interactive process control.',
      },
      {
        type: 'link',
        href: '/sessions',
        label: 'Sessions',
        description: 'Persistent PTY sessions that survive reconnects with output replay.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Access',
    category: NavigationCategory.ACCESS,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/ssh-access',
        label: 'SSH Access',
        description: 'Connect over SSH using per-sandbox Ed25519 keys via the gateway.',
      },
      {
        type: 'link',
        href: '/preview',
        label: 'Preview',
        description: 'Expose container ports publicly over HTTPS through Caddy routes.',
      },
      {
        type: 'link',
        href: '/port-allowlist',
        label: 'Port Allowlist',
        description: 'Require explicit exposure before public traffic reaches a sandbox port.',
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
