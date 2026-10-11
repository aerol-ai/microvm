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
  SANDBOXES,
  RUN_CODE,
  RUNTIMES,
  NETWORKING,
  STORAGE,
  SDKS,
  OPERATIONS,
  ENGINEERING,
  USE_CASES,
  ENTERPRISE,
}

const link = (href: string, label: string) => ({ type: 'link' as const, href, label })

// Every docs page appears exactly once, in reading order: pagination walks
// this list, so "Next" on one page is the next thing a newcomer should read.
// Keep it two levels deep (group -> page); deeper nesting is what made the old
// sidebar hard to scan.
const getDocsSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Getting Started',
    category: NavigationCategory.OVERVIEW,
    entries: [
      link('/introduction', '- Introduction'),
      // link('/quick-start', 'Quickstart'),
      link('/getting-started/local-setup', '- Local Setup'),
      link('/getting-started/single-node-setup', '- Single Node Cloud Setup'),
      link('/getting-started/cluster-setup', '- Cluster Setup'),
    ],
  },
  {
    type: 'group',
    label: 'SDKs and Tools',
    category: NavigationCategory.SDKS,
    entries: [
      link('/sdk-setup', '- SDK setup'),
      link('/cli', '- aerolvm CLI'),
      link('/mcp', '- MCP server'),
      link('/using-daytona-sdk', '- Use the Daytona SDK'),
      link('/using-e2b-sdk', '- Use the E2B SDK'),
    ],
  },
  {
    type: 'group',
    label: 'Runtimes',
    category: NavigationCategory.RUNTIMES,
    entries: [
      link('/container-sandbox', '- Containers (Docker)'),
      link('/gpu-sandboxes', '- GPU'),
      link('/gvisor-sandbox', '- gVisor'),
      link('/firecracker-sandbox', '- Firecracker'),
      link('/wasm-sandbox', '- WebAssembly (WASM)'),
      // link('/wasm-networking', 'WASM networking'),
      link('/isolate-sandbox', '- V8 isolate'),
    ],
  },
  {
    type: 'group',
    label: 'Sandboxes',
    category: NavigationCategory.SANDBOXES,
    entries: [
      link('/sandboxes', '- Create and Manage'),
      link('/ghost-sandboxes', '- Ghost(Vercel) Mode'),
      link('/images-and-snapshots', '- Images and Snapshots'),
      link('/lifecycle', '- Lifecycle'),
      link('/sandbox-env', '- Secured Env variables'),
      link('/durability', '- Durability and failover'),
      link('/exec-streaming', '- Run commands'),
      link('/file-system', '- Handle Files'),
      link('/sessions', '- Terminal sessions'),
      link('/sandbox-tags', '- Tags'),
      link('/ssh-access', '- SSH access'),
      
    ],
  },
  
  {
    type: 'group',
    label: 'Networking',
    category: NavigationCategory.NETWORKING,
    entries: [
      link('/network-access', '- Network Access'),
      link('/advanced-network-rules', '- Advanced Network Rules'),
      link('/network-usage', '- Limit Egress and Ingress'),
      link('/public-urls', '- Expose Sandbox to Public'),
      link('/custom-domains', '- Custom domains'),
      link('/tcp-ports', '- TCP and TLS ports'),
    ],
  },
  {
    type: 'group',
    label: 'Storage',
    category: NavigationCategory.STORAGE,
    entries: [
      link('/external-storage', '- Attach cloud storage'),
      link('/platform-volumes', '- Platform volumes'),
    ],
  },
  // {
  //   type: 'group',
  //   label: 'Run a Cluster',
  //   category: NavigationCategory.OPERATIONS,
  //   entries: [
  //     link('/cluster-setup', 'Cluster setup'),
  //     link('/cluster-ingress', 'Ingress nodes'),
  //     link('/cluster-secrets', 'Secrets providers'),
  //     link('/cluster-glossary', 'Glossary'),
  //     link('/dashboard', 'Dashboard'),
  //     link('/reconcile', 'Reconcile'),
  //     link('/operational-runbooks', 'Runbooks'),
  //   ],
  // },
]

// Blog posts keep the URLs they had as docs pages, because the docs link to
// them. So the blog sidebar is chosen by membership in this list, not by a
// /blog/ prefix the way use cases are.
const getBlogSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Blogs',
    category: NavigationCategory.ENGINEERING,
    entries: [link('/blog', 'All posts')],
  },
  {
    type: 'group',
    label: 'Comparisons',
    category: NavigationCategory.ENGINEERING,
    entries: [
      link('/aerolvm-vs-daytona-vs-e2b', '- AerolVM vs Daytona vs E2B'),
      link('/tcp-vs-tls-ports', '- TCP or TLS?'),
    ],
  },
  {
    type: 'group',
    label: 'How AerolVM Is Built',
    category: NavigationCategory.ENGINEERING,
    entries: [
      link('/engineering-distributed-sandbox-runtime', '- Why AerolVM exists?'),
      link('/engineering-runtime-layers', '- Engine, chassis, runtime'),
      link('/engineering-idempotency', '- Safe retries (idempotency)'),
      link('/engineering-placement-failover', '- Placement and failover'),
      link('/engineering-security-overview', '- Security, end to end'),
      link('/engineering-trust-boundary', '- Where secrets live'),
      link('/engineering-isolation', '- How sandboxes are isolated'),
      link('/engineering-sandbox-filesystem', '- What a sandbox sees on disk'),
      link('/engineering-network-defenses', '- Fencing the network'),
      link('/engineering-secret-handling', '- Keeping API keys out'),
      link('/engineering-snapshot-correctness', '- Correct snapshot clones'),
      link('/engineering-frozen-kernel-problem', '- The frozen-kernel problem'),
      link('/randomness-in-cloned-sandboxes', '- Randomness in FC clones'),
    ],
  },
  {
    type: 'group',
    label: 'Architecture',
    category: NavigationCategory.ENGINEERING,
    entries: [
      link('/firecracker-architecture', '- Firecracker architecture'),
      link('/firecracker-hydration', '- Firecracker snapshot restore'),
      link('/wasm-architecture', '- WASM architecture'),
    ],
  },
]

const blogPaths = new Set(
  getBlogSidebarConfig().flatMap(group =>
    (group.entries || []).flatMap(entry => (entry.type === 'link' ? [entry.href] : []))
  )
)

const ucp = '/use-cases/customer-facing-product-experiences'
const uca = '/use-cases/coding-agents'
const ucd = '/use-cases/data-processing-ml'

// Same two-level shape as the docs sidebar. Labels match each page's title.
// one-click-user-sandbox stays out of the sidebar, as it was before; the
// Customer-Facing Products overview still links to it.
const getUseCasesSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Use Cases',
    category: NavigationCategory.USE_CASES,
    entries: [link('/use-cases', '- All use cases')],
  },
  {
    type: 'group',
    label: 'Customer-Facing Products',
    category: NavigationCategory.USE_CASES,
    entries: [
      link(ucp, 'Overview'),
      link(`${ucp}/ai-app-hosting`, '- Host a web app from GitHub'),
      link(`${ucp}/coding-interview`, '- Coding interview platform'),
      link(`${ucp}/spawn-postgres`, '- Your own Postgres'),
      link(`${ucp}/create-upstash-redis`, '- Your own Upstash-style Redis'),
      link(`${ucp}/secure-burner-browser`, '- Burner browser'),
      link(`${ucp}/secure-burner-vpn`, '- Burner VPN proxy'),
      link(`${ucp}/gvisor-kernel-isolation-security`, '- gVisor kernel probe'),
    ],
  },
  {
    type: 'group',
    label: 'Coding Agents',
    category: NavigationCategory.USE_CASES,
    entries: [
      link(uca, 'Overview'),
      link(`${uca}/claude-code-repository-architecture-agent`, '- Generate an architecture diagram'),
      link(`${uca}/large-scale-refactor-migration-agent`, '- Make a code change and open a PR'),
      link(`${uca}/pull-request-review-auto-fix-agent`, '- Review a pull request'),
      link(`${uca}/test-writing-failure-reproduction-agent`, '- Write 500 tests'),
      link(`${uca}/claude-code-security-vulnerability-remediation-agent`, '- Find and fix security problems'),
    ],
  },
  {
    type: 'group',
    label: 'Data and ML',
    category: NavigationCategory.USE_CASES,
    entries: [
      link(`${ucd}/kaggle-to-parquet`, '- Kaggle dataset to Parquet'),
      link(`${ucd}/duckdb-dataset-explorer`, '- SQL on Kaggle with DuckDB'),
      link(`${ucd}/hyperparameter-tuning-farm`, '- Hyperparameter tuning farm'),
      link(`${ucd}/headless-jupyter-notebook`, '- Headless Jupyter notebook'),
    ],
  },
]

const ent = '/enterprise'

// The Enterprise tab, grouped the way enterprise docs usually are: start
// here, architecture, security, compliance, then support.
const getEnterpriseSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Enterprise',
    category: NavigationCategory.ENTERPRISE,
    entries: [link(ent, 'Overview')],
  },
  {
    type: 'group',
    label: 'Architecture',
    category: NavigationCategory.ENTERPRISE,
    entries: [
      link(`${ent}/architecture`, '- Security architecture'),
      link(`${ent}/deployment`, '- Reference architectures'),
    ],
  },
  {
    type: 'group',
    label: 'Security',
    category: NavigationCategory.ENTERPRISE,
    entries: [
      link(`${ent}/security-controls`, '- Security baseline'),
      link(`${ent}/hardening`, '- Hardening guide'),
      link(`${ent}/responsibility`, '- Shared responsibility'),
    ],
  },
  {
    type: 'group',
    label: 'Compliance',
    category: NavigationCategory.ENTERPRISE,
    entries: [link(`${ent}/audit-evidence`, '- Audit and compliance')],
  },
  {
    type: 'group',
    label: 'Support',
    category: NavigationCategory.ENTERPRISE,
    entries: [link(`${ent}/maintainer`, '-Work with the maintainer')],
  },
]

// The Changelog tab: one page, every release newest first. Its own sidebar
// keeps the Docs sidebar from showing on a page that is not part of it.
const getChangelogSidebarConfig = (): NavigationGroup[] => [
  {
    type: 'group',
    label: 'Changelog',
    category: NavigationCategory.ENGINEERING,
    entries: [link('/changelog', 'All releases')],
  },
]

export function isChangelogPath(pathname: string): boolean {
  return pathname === '/changelog' || pathname === '/changelog/'
}

export function isEnterprisePath(pathname: string): boolean {
  return pathname === ent || pathname.startsWith(`${ent}/`)
}

function isUseCasesPath(pathname: string): boolean {
  return pathname === '/use-cases' || pathname.startsWith('/use-cases/')
}

export function isBlogPath(pathname: string): boolean {
  return blogPaths.has(pathname.replace(/\/$/, '') || '/')
}

export const getSidebarConfig = (pathname = '/'): NavigationGroup[] => {
  if (isUseCasesPath(pathname)) return getUseCasesSidebarConfig()
  if (isEnterprisePath(pathname)) return getEnterpriseSidebarConfig()
  if (isChangelogPath(pathname)) return getChangelogSidebarConfig()
  if (isBlogPath(pathname)) return getBlogSidebarConfig()
  return getDocsSidebarConfig()
}
