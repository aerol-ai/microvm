import { satteri } from '@astrojs/markdown-satteri'
import starlight from '@astrojs/starlight'
import { defineConfig } from 'astro/config'
import mermaid from 'astro-mermaid'

export default defineConfig({
  // Pin GFM on the processor itself. Under the old remark pipeline .mdx pages
  // only got pipe tables when `gfm: true` was set explicitly, so they shipped
  // raw `| ... |` while .md pages looked fine. Astro 7 deprecated
  // `markdown.gfm` in favour of processor features; Sätteri defaults GFM on
  // today, but stating it here keeps a default flip from bringing that back.
  // @astrojs/mdx reads `features.gfm` from this processor, and Starlight adds
  // its own plugins to the same instance.
  markdown: {
    processor: satteri({ features: { gfm: true } }),
  },
  site: process.env.PUBLIC_SITE_URL || 'http://localhost:4321',
  base: process.env.PUBLIC_BASE_PATH || '/',
  outDir: './dist',
  redirects: {
    '/': '/getting-started',
  },
  integrations: [
    // Must precede starlight() so it rewrites ```mermaid fenced blocks into
    // rendered diagrams before Starlight's Shiki highlighter treats them as
    // plain code. autoTheme follows the site's light/dark toggle.
    mermaid({
      theme: 'default',
      autoTheme: true,
    }),
    starlight({
      title: 'AerolVM',
      favicon: '/favicon.svg',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/aerol-ai/microvm',
        },
      ],
      editLink: {
        baseUrl:
          'https://github.com/aerol-ai/microvm/blob/main/docs/src/content/docs/',
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 4,
      },
      customCss: ['./src/fonts/font-face.css', './src/styles/style.scss'],
      components: {
        Footer: './src/components/Footer.astro',
        MarkdownContent: './src/components/MarkdownContent.astro',
        Pagination: './src/components/Pagination.astro',
        Header: './src/components/Header.astro',
        PageSidebar: './src/components/PageSidebar.astro',
        PageFrame: './src/components/PageFrame.astro',
        Sidebar: './src/components/Sidebar.astro',
        TwoColumnContent: './src/components/TwoColumnContent.astro',
        TableOfContents: './src/components/TableOfContents.astro',
        MobileMenuToggle: './src/components/MobileMenuToggle.astro',
        ContentPanel: './src/components/ContentPanel.astro',
        PageTitle: './src/components/PageTitle.astro',
        Hero: './src/components/Hero.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
        Head: './src/components/Head.astro',
        EditLink: './src/components/EditLink.astro',
        ExploreMore: './src/components/ExploreMore.astro',
      },
    }),
  ],
})
