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
  ENGINEERING,
  OPERATIONS,
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
        href: '/comparison',
        label: 'AerolVM vs Daytona vs e2b',
        description: 'How AerolVM compares to e2b and Daytona, and why we built it.',
      },
      {
        type: 'group',
        label: 'Server Setup',
        homePageHref: '/getting-started',
        entries: [
          {
            type: 'link',
            href: '/getting-started/local-setup',
            label: 'Local Setup',
            description: 'Run AerolVM directly on your Mac or Linux machine for local development.',
          },
          {
            type: 'link',
            href: '/getting-started/single-node-setup',
            label: 'Single-Node Setup',
            description: 'Install AerolVM on one Linux host with domain, TLS, SSH, and optional GPU support.',
          },
          {
            type: 'group',
            label: 'Cluster',
            homePageHref: '/cluster-setup',
            entries: [
              {
                type: 'link',
                href: '/cluster-setup',
                label: 'Setup',
                description: 'Split a cluster into server / worker / ingress roles and front it with a single LB endpoint.',
              },
              {
                type: 'link',
                href: '/cluster-ingress',
                label: 'Ingress',
                description: 'Split a cluster into server / worker / ingress roles and front it with a single LB endpoint.',
              },
              {
                type: 'link',
                href: '/cluster-glossary',
                label: 'Glossary',
                description: 'Environment variables, node roles, and quorum reference for AerolVM clusters.',
              },
            ],
          },
        ],
      },

      {
        type: 'group',
        label: 'SDK Setup',
        homePageHref: '/sdk-setup',
        entries: [
          {
            type: 'link',
            href: '/sdk-setup',
            label: 'Using AerolVM SDK',
            description: 'Point the official AerolVM SDK facade.',
          },
          {
            type: 'link',
            href: '/using-daytona-sdk',
            label: 'Using Daytona SDK',
            description: 'Point the official Daytona SDK at AerolVM\'s /daytona compatibility facade.',
          },
          {
            type: 'link',
            href: '/using-e2b-sdk',
            label: 'Using E2B SDK',
            description: 'Point the official E2B SDK at AerolVM\'s /e2b compatibility facade.',
          },
        ],
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
        type: 'group',
        label: 'Create Sandbox',
        homePageHref: '/sandboxes',
        entries: [
          {
            type: 'link',
            href: '/sandboxes',
            label: 'Docker',
            description: 'Create, manage, and resize standard Docker sandboxes.',
          },
          {
            type: 'link',
            href: '/gpu-sandboxes',
            label: 'GPU',
            description: 'Attach NVIDIA, AMD, or Apple Silicon GPUs to a sandbox.',
          },
          {
            type: 'link',
            href: '/firecracker-sandbox',
            label: 'Firecracker',
            description: 'Full microVM isolation with sub-100ms boot times.',
          },
          {
            type: 'link',
            href: '/gvisor-sandbox',
            label: 'gVisor',
            description: 'User-space kernel isolation for untrusted code.',
          },
        ],
      },
      {
        type: 'group',
        homePageHref: '/snapshots',
        label: 'Snapshots',
        entries: [
          {
            type: 'link',
            href: '/snapshots',
            label: 'Snapshots',
            description: 'Capture a running sandbox or register an image as a named, reusable template.',
          },
          {
            type: 'link',
            href: '/firecracker-templates',
            label: 'Firecracker Templates',
            description: 'Register OCI images as Firecracker rootfs templates for sub-100ms cold starts; rebuild on demand.',
          },
        ]
      },
      {
        type: 'link',
        href: '/environment',
        label: 'Lifecycle + Environment',
        description: 'Docker image, env vars, resource limits, and idle lifecycle.',
      },
      {
        type: 'link',
        href: '/external-storage',
        label: 'Attach Volumes',
        description: 'Mount S3, NFS, SSHFS, and rclone-backed storage into sandboxes.',
      },
      {
        type: 'group',
        homePageHref: '/preview',
        label: 'Preview Publicly',
        entries: [
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
          {
            type: 'link',
            href: '/custom-domains',
            label: 'Custom Domains',
            description: 'Attach arbitrary public hostnames to a sandbox with automatic per-host HTTPS via ACME.',
          },
        ]
      },
      {
        type: 'group',
        homePageHref: '/network-usage',
        label: 'Network Usage',
        entries: [
          {
            type: 'link',
            href: '/network-usage',
            label: 'Network Usage & Quotas',
            description: 'Per-sandbox ingress / egress byte counters with optional caps that drop traffic when exceeded.',
          },
          {
            type: 'link',
            href: '/network-isolation',
            label: 'Network Isolation',
            description: 'Block egress with host-level firewall rules on a per-sandbox basis.',
          }
        ]
      },
      {
        type: 'link',
        href: '/serverless',
        label: 'Serverless',
        description: 'Auto-stop sandboxes on idle and wake them on the next inbound HTTP request.',
      },
      // {
      //   type: 'link',
      //   href: '/reconcile',
      //   label: 'Reconcile',
      //   description: 'Sync the sandbox database with live container state. Fix capacity errors after a host restart.',
      // },

      {
        type: 'link',
        href: '/sandbox-tags',
        label: 'Filter Sandbox Tags',
        description: 'Filter list responses by tag with AND semantics for multi-tenant control planes.',
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
      {
        type: 'link',
        href: '/ssh-access',
        label: 'SSH Access',
        description: 'Connect over SSH using per-sandbox Ed25519 keys via the gateway.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Important Features',
    category: NavigationCategory.FEATURES,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/serverless',
        label: 'Serverless',
        description: 'Auto-stop sandboxes on idle and wake them on the next inbound HTTP request.',
      },
      {
        type: 'link',
        href: '/durability',
        label: 'Durability & Failover',
        description: 'What survives host crashes and cluster-mode owner failover, and how to make workspace state durable.',
      },
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
        href: '/tcp-ports',
        label: 'TCP & TLS Ports',
        description: 'Publish native TCP endpoints (Postgres, Redis, MySQL, Mongo) via caddy-l4.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Operations',
    category: NavigationCategory.OPERATIONS,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/dashboard',
        label: 'Dashboard',
        description: 'Built-in operator dashboard for cluster, capacity, placements, and metrics - sign in with your PAT.',
      },
    ],
  },
  {
    type: 'group',
    label: 'Engineering',
    category: NavigationCategory.ENGINEERING,
    homePageHref: '/',
    entries: [
      {
        type: 'link',
        href: '/engineering-idempotency',
        label: 'Idempotency on a Single Writer',
        description: 'Partial unique indexes + request_idempotency replay + a one-writer SQLite core. Making concurrent-duplicate races structurally unrepresentable.',
      },
      {
        type: 'link',
        href: '/engineering-placement-failover',
        label: 'Placement & Failover',
        description: 'Raft FSM with two-stage reservations, SWIM gossip + pulled capacity, power-of-two placement, owner-sharded forwarding, dead-owner orphan/reclaim, and the Noop single-node degradation.',
      },
      {
        type: 'link',
        href: '/engineering-trust-boundary',
        label: 'Host-Mediated Trust Boundary',
        description: 'AES-256-GCM sealed credentials whose key never leaves the package, mount tools that execute on the host, cross-tenant isolation via the kernel mount namespace, and host-enforced network chokepoints.',
      },
      {
        type: 'link',
        href: '/engineering-snapshot-correctness',
        label: 'Snapshot Clone Correctness',
        description: 'Five hazards when many sandboxes resume from one snapshot: vsock-safe control channel, post-resume RNG/clock reseed, template-CID handshake, mmap-time integrity verification, CoW-aware capacity accounting.',
      },
      {
        type: 'link',
        href: '/engineering-frozen-kernel-problem',
        label: 'The Frozen-Kernel Problem',
        description: 'Two clones of one snapshot are the same machine — same RNG pool, same wall clock, same network identity. The paused-resume + vsock + post-resume reseed architecture that makes them unique before any guest code runs.',
      },
      {
        type: 'link',
        href: '/firecracker-architecture',
        label: 'Firecracker Architecture',
        description: 'Components, the jailer-isolated microVM anatomy, and the Create boot path step by step.',
      },
      {
        type: 'link',
        href: '/firecracker-hydration',
        label: 'Hydration & Operational Fold',
        description: 'Warm-VMM pool, snapshot restore with lazy load, the warm-slot state machine, and node-level resource sharing.',
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
            href: '/use-cases/customer-facing-product-experiences/secure-burner-vpn',
            label: 'Impossible to Trace Burner VPN',
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
