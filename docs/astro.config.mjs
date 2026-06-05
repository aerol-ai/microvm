import starlight from '@astrojs/starlight'
import { defineConfig } from 'astro/config'

export default defineConfig({
  // Starlight's setup replaces `markdown.remarkPlugins` but does not set `gfm`.
  // @astrojs/mdx only enables pipe tables when `gfm: true`; plain .md pages still
  // default to GFM via @astrojs/markdown-remark, which is why tables looked fine
  // in dev and on .md pages in production while .mdx pages showed raw `| ... |`.
  markdown: {
    gfm: true,
  },
  site: process.env.PUBLIC_SITE_URL || 'http://localhost:4321',
  base: process.env.PUBLIC_BASE_PATH || '/',
  outDir: './dist',
  redirects: {
    '/': '/getting-started',
  },
  integrations: [
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
