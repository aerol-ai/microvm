import { defineMiddleware } from 'astro:middleware'

import { redirects } from './utils/redirects'

export const onRequest = defineMiddleware(({ request, redirect }, next) => {
  const url = new URL(request.url)
  const path = url.pathname.replace(/\/$/, '') || '/'
  const nextPath = redirects[path]

  if (nextPath) {
    return redirect(nextPath, 301)
  }

  return next()
})