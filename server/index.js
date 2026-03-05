import Fastify from 'fastify'
import websocketPlugin from '@fastify/websocket'
import staticPlugin from '@fastify/static'
import { randomBytes } from 'crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { stmts } from './db.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ─── JWT secret ───────────────────────────────────────────────────────────────
const dataDir = join(__dirname, '../data')
mkdirSync(dataDir, { recursive: true })
const secretFile = join(dataDir, '.jwt_secret')

const JWT_SECRET = process.env.JWT_SECRET
  ?? (existsSync(secretFile)
      ? readFileSync(secretFile, 'utf8').trim()
      : (() => {
          const s = randomBytes(32).toString('hex')
          writeFileSync(secretFile, s, { mode: 0o600 })
          return s
        })())

const JWT_TTL = '7d'

// ─── Fastify ──────────────────────────────────────────────────────────────────
const app = Fastify({
  logger: { level: process.env.LOG_LEVEL ?? 'warn' },
  bodyLimit: 6_000_000,  // 6 MB – for file uploads via server path
})

await app.register(websocketPlugin)
await app.register(staticPlugin, {
  root: join(__dirname, '../client'),
  prefix: '/',
})

// ─── Security headers ─────────────────────────────────────────────────────────
app.addHook('onSend', async (req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff')
  reply.header('X-Frame-Options', 'DENY')
  reply.header('Referrer-Policy', 'no-referrer')
  // CSP: allow same-origin resources + WebRTC STUN (uses ws/wss same origin)
  reply.header(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' wss: ws:; media-src 'self' blob:; worker-src 'none'; object-src 'none'; base-uri 'self'",
  )
  // CORS: same-origin only (tighten if you add a CDN)
  const origin = req.headers.origin
  if (origin && new URL(origin).host === req.headers.host) {
    reply.header('Access-Control-Allow-Origin', origin)
    reply.header('Vary', 'Origin')
  }
})

// ─── Rate limiter ─────────────────────────────────────────────────────────────
const rl = new Map()
function rateLimit(key, max, windowMs) {
  const now = Date.now()
  let e = rl.get(key)
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + windowMs }; rl.set(key, e) }
  return ++e.count <= max
}
setInterval(() => { const now = Date.now(); for (const [k, v] of rl) if (now > v.resetAt) rl.delete(k) }, 300_000)

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_TTL })
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET) } catch { return null }
}
function requireAuth(req, reply) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) { reply.code(401).send({ error: 'Unauthorized' }); return null }
  const payload = verifyToken(header.slice(7))
  if (!payload) { reply.code(401).send({ error: 'Invalid or expired token' }); return null }
  return payload
}

// ─── Validation ───────────────────────────────────────────────────────────────
const RE_USERNAME = /^[a-zA-Z0-9_]{3,20}$/
const RE_B64      = /^[A-Za-z0-9+/]+=*$/

function validPublicKey(k) {
  return typeof k === 'string' && k.length >= 80 && k.length <= 256 && RE_B64.test(k)
}
function validCiphertext(v, maxLen = 131_072) {
  return typeof v === 'string' && v.length > 0 && v.length <= maxLen && RE_B64.test(v)
}
function validIv(v) {
  return typeof v === 'string' && v.length > 0 && v.length <= 32 && RE_B64.test(v)
}

// ─── WebSocket registry ───────────────────────────────────────────────────────
const connections = new Map() // userId → WebSocket

function broadcastOnlineStatus() {
  const names = [...connections.keys()].map(id => connections.get(id)?._username).filter(Boolean)
  const msg = JSON.stringify({ type: 'online', users: names })
  for (const [, ws] of connections) if (ws.readyState === 1) ws.send(msg)
}

function sendToGroup(groupId, payload, excludeUserId = null) {
  const members = stmts.memberIds.all(groupId)
  for (const { user_id } of members) {
    if (user_id === excludeUserId) continue
    const ws = connections.get(user_id)
    if (ws?.readyState === 1) ws.send(JSON.stringify(payload))
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, reply) => {
  if (!rateLimit(`reg:${req.ip}`, 5, 60_000))
    return reply.code(429).send({ error: 'Too many requests – try again in a minute' })

  const { username, password, publicKey } = req.body ?? {}
  if (!username || !RE_USERNAME.test(username))
    return reply.code(400).send({ error: 'Username must be 3–20 alphanumeric/underscore chars' })
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128)
    return reply.code(400).send({ error: 'Password must be 8–128 characters' })
  if (!validPublicKey(publicKey))
    return reply.code(400).send({ error: 'Invalid public key format' })

  const hash = await bcrypt.hash(password, 12)
  try {
    const result = stmts.insertUser.run(username, hash, publicKey)
    reply.code(201).send({ token: signToken({ id: result.lastInsertRowid, username }), username })
  } catch (e) {
    if (e.message.includes('UNIQUE')) return reply.code(409).send({ error: 'Username already taken' })
    throw e
  }
})

// POST /api/login
app.post('/api/login', async (req, reply) => {
  if (!rateLimit(`login:${req.ip}`, 10, 60_000))
    return reply.code(429).send({ error: 'Too many requests – try again in a minute' })

  const { username, password } = req.body ?? {}
  if (!username || !password) return reply.code(400).send({ error: 'Username and password required' })

  const user = stmts.findUser.get(username)
  const hash = user?.password_hash ?? '$2a$12$invalidhashtopreventtiming000000000000'
  const ok   = await bcrypt.compare(password, hash)
  if (!user || !ok) return reply.code(401).send({ error: 'Invalid username or password' })

  reply.send({ token: signToken(user), username: user.username })
})

// PUT /api/users/me/key
app.put('/api/users/me/key', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const { publicKey } = req.body ?? {}
  if (!validPublicKey(publicKey)) return reply.code(400).send({ error: 'Invalid public key format' })
  stmts.updatePubKey.run(publicKey, auth.id)
  reply.send({ ok: true })
})

// GET /api/users
app.get('/api/users', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  reply.send(stmts.listUsers.all(auth.id).map(u => u.username))
})

// GET /api/users/:username/key
app.get('/api/users/:username/key', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const row = stmts.userPubKey.get(req.params.username)
  if (!row) return reply.code(404).send({ error: 'User not found' })
  reply.send({ publicKey: row.public_key })
})

// GET /api/messages/:username
app.get('/api/messages/:username', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const other = stmts.findUser.get(req.params.username)
  if (!other) return reply.code(404).send({ error: 'User not found' })
  reply.send(stmts.conversation.all(auth.id, other.id, other.id, auth.id))
})

// ─── Group routes ─────────────────────────────────────────────────────────────

// POST /api/groups  { name, members: [username,...], groupKeys: {username: {ciphertext,iv}} }
app.post('/api/groups', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const { name, members, groupKeys } = req.body ?? {}

  if (!name || typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 50)
    return reply.code(400).send({ error: 'Group name must be 1–50 characters' })
  if (!Array.isArray(members) || members.length === 0)
    return reply.code(400).send({ error: 'members array required' })
  if (!groupKeys || typeof groupKeys !== 'object')
    return reply.code(400).send({ error: 'groupKeys required' })

  const trimmedName = name.trim()
  const allMembers  = [...new Set([auth.username, ...members])].filter(u => RE_USERNAME.test(u))
  if (allMembers.length > 50) return reply.code(400).send({ error: 'Max 50 members' })

  const createTx = stmts.createGroup.database.transaction(() => {
    const { id: groupId } = stmts.createGroup.get(trimmedName, auth.id)
    stmts.addMember.run(groupId, auth.id, 'owner')

    for (const username of allMembers) {
      if (username === auth.username) continue
      const user = stmts.findUser.get(username)
      if (!user) continue
      stmts.addMember.run(groupId, user.id, 'member')

      const gk = groupKeys[username]
      if (gk && validCiphertext(gk.ciphertext, 256) && validIv(gk.iv)) {
        stmts.setGroupKey.run(groupId, user.id, auth.username, gk.ciphertext, gk.iv)
      }
    }
    // Key for owner themselves
    const ownerKey = groupKeys[auth.username]
    if (ownerKey && validCiphertext(ownerKey.ciphertext, 256) && validIv(ownerKey.iv)) {
      stmts.setGroupKey.run(groupId, auth.id, auth.username, ownerKey.ciphertext, ownerKey.iv)
    }
    return groupId
  })

  const groupId = createTx()

  // Notify online members
  const group = { id: groupId, name: trimmedName, owner: auth.username }
  sendToGroup(groupId, { type: 'group-added', group }, auth.id)

  reply.code(201).send({ id: groupId })
})

// GET /api/groups
app.get('/api/groups', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  reply.send(stmts.listMyGroups.all(auth.id))
})

// GET /api/groups/:id
app.get('/api/groups/:id', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId = Number(req.params.id)
  if (!stmts.isMember.get(groupId, auth.id)) return reply.code(403).send({ error: 'Not a member' })
  const group   = stmts.findGroup.get(groupId)
  if (!group) return reply.code(404).send({ error: 'Group not found' })
  const members = stmts.groupMembers.all(groupId)
  reply.send({ ...group, members })
})

// GET /api/groups/:id/key  – fetch encrypted group key for current user
app.get('/api/groups/:id/key', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId = Number(req.params.id)
  if (!stmts.isMember.get(groupId, auth.id)) return reply.code(403).send({ error: 'Not a member' })
  const row = stmts.getGroupKey.get(groupId, auth.id)
  if (!row) return reply.code(404).send({ error: 'Key not provisioned' })
  reply.send(row)
})

// GET /api/groups/:id/messages
app.get('/api/groups/:id/messages', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId = Number(req.params.id)
  if (!stmts.isMember.get(groupId, auth.id)) return reply.code(403).send({ error: 'Not a member' })
  const rows = stmts.groupMessages.all(groupId).map(r => ({
    ...r,
    meta: r.meta ? JSON.parse(r.meta) : null,
  }))
  reply.send(rows)
})

// POST /api/groups/:id/members  { username, encryptedKey: {ciphertext, iv} }
app.post('/api/groups/:id/members', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId  = Number(req.params.id)
  const myRole   = stmts.memberRole.get(groupId, auth.id)
  if (!myRole || !['owner','admin'].includes(myRole.role)) return reply.code(403).send({ error: 'Admin only' })

  const { username, encryptedKey } = req.body ?? {}
  if (!username || !RE_USERNAME.test(username)) return reply.code(400).send({ error: 'Invalid username' })
  const user = stmts.findUser.get(username)
  if (!user) return reply.code(404).send({ error: 'User not found' })

  const { n } = stmts.memberCount.get(groupId)
  if (n >= 50) return reply.code(400).send({ error: 'Group is full (50 max)' })

  stmts.addMember.run(groupId, user.id, 'member')

  if (encryptedKey && validCiphertext(encryptedKey.ciphertext, 256) && validIv(encryptedKey.iv)) {
    stmts.setGroupKey.run(groupId, user.id, auth.username, encryptedKey.ciphertext, encryptedKey.iv)
  }

  const group = stmts.findGroup.get(groupId)
  const ws    = connections.get(user.id)
  if (ws?.readyState === 1) {
    ws.send(JSON.stringify({ type: 'group-added', group: { id: groupId, name: group.name, owner: auth.username } }))
  }
  sendToGroup(groupId, { type: 'group-member-added', groupId, username }, auth.id)

  reply.send({ ok: true })
})

// DELETE /api/groups/:id/members/:username
app.delete('/api/groups/:id/members/:username', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId  = Number(req.params.id)
  const target   = req.params.username
  const myRole   = stmts.memberRole.get(groupId, auth.id)

  // Owner can remove anyone; admin can remove regular members; member can remove themselves
  const canRemove =
    myRole?.role === 'owner' ||
    myRole?.role === 'admin' ||
    target === auth.username
  if (!canRemove) return reply.code(403).send({ error: 'Forbidden' })

  const user = stmts.findUser.get(target)
  if (!user) return reply.code(404).send({ error: 'User not found' })
  if (!stmts.isMember.get(groupId, user.id)) return reply.code(404).send({ error: 'Not a member' })
  if (stmts.memberRole.get(groupId, user.id)?.role === 'owner')
    return reply.code(400).send({ error: 'Cannot remove group owner' })

  stmts.removeMember.run(groupId, user.id)

  sendToGroup(groupId, { type: 'group-member-removed', groupId, username: target })
  const ws = connections.get(user.id)
  if (ws?.readyState === 1) ws.send(JSON.stringify({ type: 'group-removed', groupId }))

  reply.send({ ok: true })
})

// ─── Poll routes ──────────────────────────────────────────────────────────────

// GET /api/groups/:id/polls
app.get('/api/groups/:id/polls', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId = Number(req.params.id)
  if (!stmts.isMember.get(groupId, auth.id)) return reply.code(403).send({ error: 'Not a member' })

  const polls = stmts.groupPolls.all(groupId).map(p => ({
    ...p,
    options: JSON.parse(p.options),
    votes:   stmts.pollVotes.all(p.id),
    myVotes: stmts.userVotes.all(p.id, auth.id).map(r => r.option_idx),
  }))
  reply.send(polls)
})

// POST /api/groups/:id/polls  { question, options: [str,...], multi? }
app.post('/api/groups/:id/polls', async (req, reply) => {
  const auth = requireAuth(req, reply); if (!auth) return
  const groupId = Number(req.params.id)
  if (!stmts.isMember.get(groupId, auth.id)) return reply.code(403).send({ error: 'Not a member' })

  const { question, options, multi = false } = req.body ?? {}
  if (!question || typeof question !== 'string' || question.length < 1 || question.length > 500)
    return reply.code(400).send({ error: 'Question must be 1–500 chars' })
  if (!Array.isArray(options) || options.length < 2 || options.length > 8)
    return reply.code(400).send({ error: '2–8 options required' })
  for (const o of options) {
    if (typeof o !== 'string' || o.length < 1 || o.length > 100)
      return reply.code(400).send({ error: 'Each option must be 1–100 chars' })
  }

  const row = stmts.createPoll.get(groupId, auth.id, question.trim(), JSON.stringify(options), multi ? 1 : 0)
  const poll = {
    id: row.id, groupId, question: question.trim(), options, multi: multi ? 1 : 0,
    creator: auth.username, votes: [], myVotes: [], created_at: row.created_at,
  }

  sendToGroup(groupId, { type: 'group-poll', groupId, poll })
  reply.code(201).send(poll)
})

// POST /api/polls/:id/vote  { optionIdx }
app.post('/api/polls/:id/vote', async (req, reply) => {
  const auth   = requireAuth(req, reply); if (!auth) return
  const pollId = Number(req.params.id)
  const poll   = stmts.getPoll.get(pollId)
  if (!poll) return reply.code(404).send({ error: 'Poll not found' })
  if (!stmts.isMember.get(poll.group_id, auth.id)) return reply.code(403).send({ error: 'Not a member' })

  const { optionIdx } = req.body ?? {}
  const options = JSON.parse(poll.options)
  if (typeof optionIdx !== 'number' || optionIdx < 0 || optionIdx >= options.length)
    return reply.code(400).send({ error: 'Invalid option' })

  if (!poll.multi) stmts.clearVotes.run(pollId, auth.id) // single-choice: replace vote
  stmts.addVote.run(pollId, auth.id, optionIdx)

  const votes = stmts.pollVotes.all(pollId)
  sendToGroup(poll.group_id, { type: 'poll-update', pollId, groupId: poll.group_id, votes })
  reply.send({ ok: true, votes })
})

// DELETE /api/polls/:id/vote  { optionIdx }
app.delete('/api/polls/:id/vote', async (req, reply) => {
  const auth   = requireAuth(req, reply); if (!auth) return
  const pollId = Number(req.params.id)
  const poll   = stmts.getPoll.get(pollId)
  if (!poll) return reply.code(404).send({ error: 'Poll not found' })
  if (!stmts.isMember.get(poll.group_id, auth.id)) return reply.code(403).send({ error: 'Not a member' })

  const { optionIdx } = req.body ?? {}
  stmts.removeVote.run(pollId, auth.id, optionIdx ?? 0)

  const votes = stmts.pollVotes.all(pollId)
  sendToGroup(poll.group_id, { type: 'poll-update', pollId, groupId: poll.group_id, votes })
  reply.send({ ok: true, votes })
})

// ─── WebSocket /ws  (token sent in first JSON message, not in URL) ───────────
app.register(async (scope) => {
  scope.get('/ws', { websocket: true }, (socket) => {
    // Auth handshake: wait for first message { type:'auth', token }
    let userId   = null
    let username = null
    let authed   = false

    // Per-socket rate limit counters
    const WS_RL_WINDOW   = 10_000   // 10 s window
    const WS_RL_MAX_MSG  = 60       // max messages per window
    const WS_RL_MAX_FILE = 4        // max file messages per window
    let rlCount     = 0
    let rlFileCount = 0
    let rlResetAt   = Date.now() + WS_RL_WINDOW

    function wsRateOk(isFile = false) {
      const now = Date.now()
      if (now > rlResetAt) { rlCount = 0; rlFileCount = 0; rlResetAt = now + WS_RL_WINDOW }
      if (++rlCount > WS_RL_MAX_MSG) return false
      if (isFile && ++rlFileCount > WS_RL_MAX_FILE) return false
      return true
    }

    // Auth timeout: close if no auth within 5 s
    const authTimeout = setTimeout(() => {
      if (!authed) socket.close(4001, 'Auth timeout')
    }, 5_000)

    socket.on('message', (rawData) => {
      let msg
      try { msg = JSON.parse(rawData.toString()) } catch { return }

      // ── Auth handshake ────────────────────────────────────────────────────
      if (!authed) {
        if (msg.type !== 'auth' || typeof msg.token !== 'string') {
          socket.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }))
          socket.close(4001, 'Unauthorized')
          return
        }
        const payload = verifyToken(msg.token)
        if (!payload) {
          socket.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }))
          socket.close(4001, 'Unauthorized')
          return
        }
        clearTimeout(authTimeout)
        authed   = true
        userId   = payload.id
        username = payload.username
        socket._username = username

        const existing = connections.get(userId)
        if (existing?.readyState === 1) {
          existing.send(JSON.stringify({ type: 'info', message: 'Session replaced' }))
          existing.close(4000, 'Replaced')
        }
        connections.set(userId, socket)
        socket.send(JSON.stringify({ type: 'auth-ok' }))
        broadcastOnlineStatus()
        return
      }

      // ── Authenticated messages ────────────────────────────────────────────

      // ── P2P signaling relay ───────────────────────────────────────────────
      if (msg.type === 'signal') {
        if (!wsRateOk()) return
        const { to, payload } = msg
        if (!to || typeof to !== 'string' || !payload || typeof payload !== 'object') return
        const recipient = stmts.findUser.get(to)
        if (!recipient) return
        const rws = connections.get(recipient.id)
        if (rws?.readyState === 1) rws.send(JSON.stringify({ type: 'signal', from: username, payload }))
        return
      }

      // ── Typing indicator relay ────────────────────────────────────────────
      if (msg.type === 'typing') {
        const { to } = msg
        if (!to || typeof to !== 'string') return
        const recipient = stmts.findUser.get(to)
        if (!recipient) return
        const rws = connections.get(recipient.id)
        if (rws?.readyState === 1) rws.send(JSON.stringify({ type: 'typing', from: username, isTyping: !!msg.isTyping }))
        return
      }

      // ── 1-1 message (offline fallback) ────────────────────────────────────
      if (msg.type === 'message') {
        const isFile = msg.msgType === 'file'
        if (!wsRateOk(isFile)) return
        const { to, ciphertext, iv, msgType = 'text', meta } = msg
        if (!to || typeof to !== 'string') return
        const maxLen = isFile ? 5_500_000 : 131_072
        if (!validCiphertext(ciphertext, maxLen) || !validIv(iv)) return
        const metaStr = meta && typeof meta === 'object' ? JSON.stringify(meta) : null

        const recipient = stmts.findUser.get(to)
        if (!recipient) return

        const result = stmts.insertMsg.run(userId, recipient.id, msgType, ciphertext, iv, metaStr)
        const envelope = {
          type: 'message', id: result.lastInsertRowid, from: username,
          msgType, ciphertext, iv, meta: meta ?? null,
          createdAt: Math.floor(Date.now() / 1000),
        }
        const rws = connections.get(recipient.id)
        if (rws?.readyState === 1) rws.send(JSON.stringify(envelope))
        socket.send(JSON.stringify({ ...envelope, type: 'sent', to }))
        return
      }

      // ── Group message ─────────────────────────────────────────────────────
      if (msg.type === 'group-message') {
        const isFile = msg.msgType === 'file'
        if (!wsRateOk(isFile)) return
        const { groupId, ciphertext, iv, msgType = 'text', meta } = msg
        if (typeof groupId !== 'number') return
        const maxLen = isFile ? 5_500_000 : 131_072
        if (!validCiphertext(ciphertext, maxLen) || !validIv(iv)) return
        const metaStr = meta && typeof meta === 'object' ? JSON.stringify(meta) : null

        // Atomic: membership check + insert in single transaction
        const row = stmts.db.transaction(() => {
          if (!stmts.isMember.get(groupId, userId)) return null
          return stmts.insertGroupMsg.get(groupId, userId, msgType, ciphertext, iv, metaStr)
        })()
        if (!row) return

        const envelope = {
          type: 'group-message', id: row.id, groupId, from: username,
          msgType, ciphertext, iv, meta: meta ?? null, createdAt: row.created_at,
        }
        sendToGroup(groupId, envelope, userId)
        socket.send(JSON.stringify({ ...envelope, type: 'group-sent' }))
        return
      }
    })

    socket.on('close', () => {
      clearTimeout(authTimeout)
      if (userId) { connections.delete(userId); broadcastOnlineStatus() }
    })
    socket.on('error', () => { if (userId) connections.delete(userId) })
  })
})

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = Number(process.env.PORT ?? 3000)
const HOST = process.env.HOST ?? '0.0.0.0'

try {
  await app.listen({ port: PORT, host: HOST })
  console.log(`msngr listening on http://${HOST}:${PORT}`)
} catch (err) {
  console.error(err)
  process.exit(1)
}
