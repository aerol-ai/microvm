// The docs are static files served from ./dist. This Worker only answers the
// page-feedback endpoint and hands every other request to the static assets.
// Static files are matched first, so the Worker runs only for paths that are
// not a file, which keeps it off the hot path for normal page loads.
import { handleFeedback } from './feedback.js'

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname.endsWith('/api/feedback')) {
      return handleFeedback(request, env)
    }
    return env.ASSETS.fetch(request)
  },
}
