import { docsLoader } from '@astrojs/starlight/loaders'
import { docsSchema } from '@astrojs/starlight/schema'
import { defineCollection } from 'astro:content'
import { z } from 'astro/zod'

import type { NavigationGroup } from './utils/navigation'

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
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
        href: '/gpu-sandboxes',
        label: 'GPU Sandboxes',
        description: 'Attach NVIDIA, AMD, or Apple Silicon GPUs to a sandbox.',
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
        href: '/preview',
        label: 'Preview',
        description: 'Expose container ports publicly over HTTPS through Caddy routes.',
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
        href: '/tcp-ports',
        label: 'TCP & TLS Ports',
        description: 'Publish native TCP endpoints (Postgres, Redis, MySQL, Mongo) via caddy-l4.',
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
        type: 'group',
        label: 'Customer-Facing Product Experiences',
        entries: [
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/ai-app-hosting',
            label: 'Live preview URLs for Web apps',
            description: 'Clone, build, and host a Bun website inside a disposable sandbox.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/secure-burner-browser',
            label: 'Secure burner browser',
            description: 'Launch a disposable Chromium desktop in a sandbox and stream it into the browser over noVNC.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/gvisor-kernel-isolation-security',
            label: 'gVisor kernel secure sandbox',
            description: 'Compare privileged-operation probes across Docker and gVisor runtimes to show how gVisor reduces direct host-kernel exposure.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/spawn-postgres',
            label: 'Deploy your own Supabase',
            description: 'Run a dedicated Postgres instance in a sandbox and expose an HTTP admin surface on a public URL.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/create-upstash-redis',
            label: 'Create your own Upstash Redis',
            description: 'Run a dedicated Redis instance in a sandbox and expose an HTTP admin surface on a public URL.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/coding-interview',
            label: 'Create Coding Interview Platform',
            description: 'Back tutorials and labs with per-user sandboxes and persistent shells.',
          },
          {
            type: 'link',
            href: '/use-cases/customer-facing-product-experiences/secure-burner-browser',
            label: 'Secure Burner Browser',
            description: 'Launch a disposable Chromium desktop in a sandbox and stream it into the browser over noVNC.',
          },
          // {
          //   type: 'link',
          //   href: '/use-cases/customer-facing-product-experiences/one-click-user-sandbox',
          //   label: 'One-click user sandbox per workspace',
          //   description: 'Provision an isolated sandbox as part of each product workspace.',
          // },
        ],
      },
      {
        type: 'group',
        label: 'AI Coding Agents & Harness Engineering',
        entries: [
          {
            type: 'link',
            href: '/use-cases/coding-agents/claude-code-repository-architecture-agent',
            label: 'Generate architecture diagram',
            description: 'Clone a real repository, run Claude headlessly, and generate arch.md.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/large-scale-refactor-migration-agent',
            label: 'Zero-shot code execution agent',
            description: 'Take a repository URL plus a code-change prompt, run Claude inside the repo, and raise a PR automatically.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/pull-request-review-auto-fix-agent',
            label: 'GitHub PR review agent',
            description: 'Check out a real PR from its URL, post a GitHub review, and export any safe fixes.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/test-writing-failure-reproduction-agent',
            label: 'Write 500 test cases',
            description: 'Clone a repository, have Claude generate 500 tests, and fail the run below a 90% completion threshold.',
          },
          {
            type: 'link',
            href: '/use-cases/coding-agents/claude-code-security-vulnerability-remediation-agent',
            label: 'Security vulnerability and Fix agent',
            description: 'Scan CVEs across repository types, apply safe fixes with Claude, and raise a PR automatically.',
          },

        ],
      },
      
      {
        type: 'group',
        label: 'Data Processing & ML',
        entries: [
          {
            type: 'link',
            href: '/use-cases/data-processing-ml/kaggle-to-parquet',
            label: 'Kaggle Dataset to Parquet',
            description: 'Download a large dataset from Kaggle, process it using Polars inside an AerolVM sandbox, and export the optimized Parquet file.',
          },
          {
            type: 'link',
            href: '/use-cases/data-processing-ml/duckdb-dataset-explorer',
            label: 'SQL on Kaggle with DuckDB',
            description: 'Launch a DuckDB instance inside a sandbox to run SQL queries directly on Kaggle datasets without a traditional database setup.',
          },
          {
            type: 'link',
            href: '/use-cases/data-processing-ml/hyperparameter-tuning-farm',
            label: 'Hyperparameter Tuning Farm',
            description: 'Spin up multiple concurrent sandboxes to test different model configurations in parallel.',
          },
          {
            type: 'link',
            href: '/use-cases/data-processing-ml/headless-jupyter-notebook',
            label: 'Headless Jupyter Notebook',
            description: 'Spin up a full JupyterLab environment in a sandbox and access it via a public URL.',
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
