import type { Site, Ui, Features } from './types'

export const SITE: Site = {
  website: 'https://astro-antfustyle-theme.vercel.app/',
  base: '/',
  title: 'Tech & Daily',
  description:
    '学习记录|生活分享',
  author: 'NickyWU',
  lang: 'zh',
  ogLocale: 'zh_CN',
  imageDomains: ['', ''],
}

export const UI: Ui = {
  internalNavs: [
    {
      path: '/blog',
      title: 'Blog',
      displayMode: 'alwaysText',
      text: 'Blog',
    },
    {
      path: '/projects',
      title: 'Projects',
      displayMode: 'alwaysText',
      text: 'Projects',
    },
    /*{
      path: '/highlights',
      title: 'Highlights',
      displayMode: 'iconToTextOnMobile',
      text: 'Highlights',
      icon: 'i-ri-screenshot-line',
    },
    {
      path: '/photos',
      title: 'Photos',
      displayMode: 'iconToTextOnMobile',
      text: 'Photos',
      icon: 'i-ri-camera-ai-line',
    },*/
    {
      path: '/shorts',
      title: 'Shorts',
      displayMode: 'iconToTextOnMobile',
      text: 'Shorts',
      icon: 'i-meteor-icons-grid',
    },
    /*{
      path: '/Media',
      title: 'Media',
      displayMode: 'iconToTextOnMobile',
      text: 'Media',
      icon: 'i-ri-draft-line',
    },*/
  ],
  socialLinks: [
    {
      link: 'https://github.com/nickyl07',
      title: 'Github',
      displayMode: 'alwaysIcon',
      icon: 'i-uil-github-alt',
    },
    {
      link: 'https://x.com/noknoku07_nok',
      title: 'Twitter',
      displayMode: 'alwaysIcon',
      icon: 'i-ri-twitter-x-fill',
    },
    /*{
      link: 'https://bsky.app/profile/astro.build',
      title: 'Astro on Bluesky',
      displayMode: 'alwaysIcon',
      icon: 'i-meteor-icons-bluesky',
    },*/
  ],
  navBarLayout: {
    left: [],
    right: [
      'internalNavs',
      'hr',
      'socialLinks',
      'hr',
      'searchButton',
      'themeButton',
      'rssLink',
    ],
    mergeOnMobile: true,
  },
  tabbedLayoutTabs: [
    { title: 'Changelog', path: '/changelog' },
    { title: '', path: '/' },
    { title: '', path: '/' },
  ],
  groupView: {
    maxGroupColumns: 3,
    showGroupItemColorOnHover: true,
  },
  githubView: {
    monorepos: [
      'withastro/astro',
      'withastro/starlight',
      'lin-stephanie/astro-loaders',
    ],
    mainLogoOverrides: [
      [/starlight/, 'https://starlight.astro.build/favicon.svg'],
    ],
    subLogoMatches: [
      [/theme/, 'i-unjs-theme-colors'],
      [/github/, 'https://github.githubassets.com/favicons/favicon.svg'],
      [/tweet/, 'i-logos-twitter'],
      [/bluesky/, 'i-logos-bluesky'],
    ],
  },
  externalLink: {
    newTab: false,
    cursorType: '',
    showNewTabIcon: false,
  },
  postMetaStyle: 'minimal',
}

/**
 * Configures whether to enable special features:
 *  - Set to `false` or `[false, {...}]` to disable the feature.
 *  - Set to `[true, {...}]` to enable and configure the feature.
 */
export const FEATURES: Features = {
  slideEnterAnim: [true, { enterStep: 60 }],
  ogImage: [
    true,
    {
      authorOrBrand: `${SITE.title}`,
      fallbackTitle: `${SITE.description}`,
      fallbackBgType: 'dot',
    },
  ],
  toc: [
    true,
    {
      minHeadingLevel: 2,
      maxHeadingLevel: 4,
      displayPosition: 'left',
      displayMode: 'content',
    },
  ],
  share: [
    true,
    {
      twitter: [true, '@noknoku07_nok'],
      bluesky: false,
      mastodon: false,
      facebook: false,
      pinterest: false,
      reddit: false,
      telegram: false,
      whatsapp: false,
      email: false,
    },
  ],
  giscus: [
    true,
    {
      'data-repo': 'nickyl07/nicky.cool',
      'data-repo-id': 'R_kgDOLylKbA',
      'data-category': 'Giscus',
      'data-category-id': 'DIC_kwDOLylKbM4Cpugn',
      'data-mapping': 'title',
      'data-strict': '0',
      'data-reactions-enabled': '1',
      'data-emit-metadata': '0',
      'data-input-position': 'bottom',
      'data-lang': 'zh-CN',
    },
  ],
  search: [
    true,
    {
      includes: ['blog', 'projects'],
      filter: true,
      navHighlight: true,
      batchLoadSize: [true, 5],
      maxItemsPerPage: [true, 3],
    },
  ],
}
