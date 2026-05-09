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
  USE_CASES,
}

const getDocsSidebarConfig = (): NavigationGroup[] => [
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
      {
        type: 'link',
        href: '/reconcile',
        label: 'Reconcile',
        description: 'Sync the sandbox database with live container state. Fix capacity errors after a host restart.',
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

const getUseCasesSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Use Cases',
    category: NavigationCategory.USE_CASES,
    entries: [
      {
        type: 'link',
        href: '/use-cases',
        label: 'Overview',
        description: 'Top-priority AerolVM use cases selected from the planning matrix.',
        exact: true,
      },
      {
        type: 'group',
        label: 'Coding Agents & Autonomous Engineering',
        entries: [
          {
            type: 'link',
            href: '/use-cases/coding-agents/autonomous-issue-to-pr-agent',
            label: 'Autonomous issue-to-PR agent',
            description: 'Take a repository task from intake to validated patch output.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/pull-request-review-auto-fix-agent',
            label: 'Pull-request review and auto-fix agent',
            description: 'Review a PR in isolation and generate a safe follow-up patch.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/test-writing-failure-reproduction-agent',
            label: 'Test-writing and failure reproduction agent',
            description: 'Turn a bug report into failing tests and a reproducible harness.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/dependency-upgrade-compatibility-agent',
            label: 'Dependency upgrade and compatibility agent',
            description: 'Upgrade dependencies, run the matrix, and export the results.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/large-scale-refactor-migration-agent',
            label: 'Large-scale refactor or migration agent',
            description: 'Run long codemods and staged migrations with streamed progress.',
          },
        ],
      },
      {
        type: 'group',
        label: 'Customer-Facing Product Experiences',
        entries: [
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/embedded-code-runner',
            label: 'Embedded code runner inside a SaaS product',
            description: 'Execute user code safely behind strong isolation boundaries.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/live-preview-urls',
            label: 'Live preview URLs for generated apps or APIs',
            description: 'Turn generated files into running previews with public URLs.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/interactive-tutorial-lab-backend',
            label: 'Interactive tutorial or lab backend',
            description: 'Back tutorials and labs with per-user sandboxes and persistent shells.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/ai-app-builder-runtime',
            label: 'AI app builder runtime',
            description: 'Compile, boot, and preview generated projects inside disposable sandboxes.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/one-click-user-sandbox',
            label: 'One-click user sandbox per workspace',
            description: 'Provision an isolated sandbox as part of each product workspace.',
          },
        ],
      },
    ],
  },
]

function isUseCasesPath(pathname: string): boolean {
  return pathname === '/use-cases' || pathname.startsWith('/use-cases/')
}

export const getSidebarConfig = (pathname = '/'): NavigationGroup[] =>
  isUseCasesPath(pathname) ? getUseCasesSidebarConfig() : getDocsSidebarConfig()
