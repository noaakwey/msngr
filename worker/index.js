// Cloudflare Worker: serves static assets and proxies /api/* + /ws to backend
// Edit BACKEND to match your Fly.io app name before deploying.
const BACKEND = 'https://msngr-ваше-имя.fly.dev'

export default {
  async fetch(req, env) {
    const url = new URL(req.url)

    if (url.pathname.startsWith('/api/') || url.pathname === '/ws') {
      const target = new URL(url.pathname + url.search, BACKEND)
      return fetch(target.toString(), {
        method:  req.method,
        headers: req.headers,
        body:    ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
      })
    }

    return env.ASSETS.fetch(req)
  },
}
