import Fastify from 'fastify'
import websocketPlugin from '@fastify/websocket'
import staticPlugin from '@fastify/static'
import { randomBytes, createHash } from 'crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { stmts } from './db.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ─── JWT secret – persisted across restarts ───────────────────────────────────
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

// ─── Fastify instance ─────────────────────────────────────────────────────────
const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? 'warn' } })

await app.register(websocketPlugin)
await app.register(staticPlugin, {
  root: join(__dirname, '../client'),
  prefix: '/',
})

// ─── Simple in-memory rate limiter ────────────────────────────────────────────
const rl = new Map() // key → { count, resetAt }

function rateLimit(key, max, windowMs) {
  const now = Date.now()
  let entry = rl.get(key)
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs }
    rl.set(key, entry)
  }
  entry.count++
  return entry.count <= max
}

// Clean stale entries every 5 min
setInterval(() => {
  const now = Date.now()
  for (const [k, v] of rl) if (now > v.resetAt) rl.delete(k)
}, 300_000)

// ─── Auth helpers ─────────────────────────────────────────────────────────────
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_TTL })
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET) } catch { return null }
}

function requireAuth(req, reply) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    reply.code(401).send({ error: 'Unauthorized' })
    return null
  }
  const payload = verifyToken(header.slice(7))
  if (!payload) { reply.code(401).send({ error: 'Invalid or expired token' }); return null }
  return payload
}

// ─── Validation ───────────────────────────────────────────────────────────────
const RE_USERNAME = /^[a-zA-Z0-9_]{3,20}$/
// Base64 string up to 256 chars (uncompressed P-256 public key = 87 chars base64)
const RE_B64 = /^[A-Za-z0-9+/]+=*$/

function validPublicKey(k) {
  return typeof k === 'string' && k.length >= 80 && k.length <= 256 && RE_B64.test(k)
}

// ─── WebSocket connection registry ───────────────────────────────────────────
// userId → WebSocket
const connections = new Map()

function broadcastOnlineStatus() {
  const onlineUsernames = [...connections.keys()].map(id => {
    // cache from token payload stored on socket object
    return connections.get(id)?._username
  }).filter(Boolean)

  const msg = JSON.stringify({ type: 'online', users: onlineUsernames })
  for (const [, ws] of connections) {
    if (ws.readyState === 1) ws.send(msg)
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/register
app.post('/api/register', async (req, reply) => {
  const ip = req.ip
  if (!rateLimit(`reg:${ip}`, 5, 60_000)) {
    return reply.code(429).send({ error: 'Too many requests – try again in a minute' })
  }

  const { username, password, publicKey } = req.body ?? {}

  if (!username || !RE_USERNAME.test(username)) {
    return reply.code(400).send({ error: 'Username must be 3–20 alphanumeric/underscore chars' })
  }
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return reply.code(400).send({ error: 'Password must be 8–128 characters' })
  }
  if (!validPublicKey(publicKey)) {
    return reply.code(400).send({ error: 'Invalid public key format' })
  }

  const hash = await bcrypt.hash(password, 12)

  try {
    const result = stmts.insertUser.run(username, hash, publicKey)
    const token = signToken({ id: result.lastInsertRowid, username })
    reply.code(201).send({ token, username })
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return reply.code(409).send({ error: 'Username already taken' })
    }
    throw e
  }
})

// POST /api/login
app.post('/api/login', async (req, reply) => {
  const ip = req.ip
  if (!rateLimit(`login:${ip}`, 10, 60_000)) {
    return reply.code(429).send({ error: 'Too many requests – try again in a minute' })
  }

  const { username, password } = req.body ?? {}
  if (!username || !password) {
    return reply.code(400).send({ error: 'Username and password required' })
  }

  const user = stmts.findUser.get(username)
  // Constant-time: always run bcrypt even on unknown user (with a dummy hash)
  const hash = user?.password_hash ?? '$2a$12$invalidhashtopreventtiming000000000000'
  const ok = await bcrypt.compare(password, hash)

  if (!user || !ok) {
    return reply.code(401).send({ error: 'Invalid username or password' })
  }

  reply.send({ token: signToken(user), username: user.username })
})

// PUT /api/users/me/key  (rotate public key – for new device setup)
app.put('/api/users/me/key', async (req, reply) => {
  const auth = requireAuth(req, reply)
  if (!auth) return

  const { publicKey } = req.body ?? {}
  if (!validPublicKey(publicKey)) {
    return reply.code(400).send({ error: 'Invalid public key format' })
  }

  stmts.updatePubKey.run(publicKey, auth.id)
  reply.send({ ok: true })
})

// GET /api/users
app.get('/api/users', async (req, reply) => {
  const auth = requireAuth(req, reply)
  if (!auth) return
  reply.send(stmts.listUsers.all(auth.id).map(u => u.username))
})

// GET /api/users/:username/key
app.get('/api/users/:username/key', async (req, reply) => {
  const auth = requireAuth(req, reply)
  if (!auth) return

  const row = stmts.userPubKey.get(req.params.username)
  if (!row) return reply.code(404).send({ error: 'User not found' })
  reply.send({ publicKey: row.public_key })
})

// GET /api/messages/:username
app.get('/api/messages/:username', async (req, reply) => {
  const auth = requireAuth(req, reply)
  if (!auth) return

  const other = stmts.findUser.get(req.params.username)
  if (!other) return reply.code(404).send({ error: 'User not found' })

  const rows = stmts.conversation.all(auth.id, other.id, other.id, auth.id)
  reply.send(rows)
})

// ─── WebSocket /ws?token=… ───────────────────────────────────────────────────
app.register(async (scope) => {
  scope.get('/ws', { websocket: true }, (socket, req) => {
    const payload = verifyToken(req.query?.token)
    if (!payload) {
      socket.send(JSON.stringify({ type: 'error', message: 'Unauthorized' }))
      socket.close(4001, 'Unauthorized')
      return
    }

    const { id: userId, username } = payload
    socket._username = username

    // Close previous connection from same user (e.g. duplicate tab)
    const existing = connections.get(userId)
    if (existing && existing.readyState === 1) {
      existing.send(JSON.stringify({ type: 'info', message: 'Session replaced' }))
      existing.close(4000, 'Replaced')
    }

    connections.set(userId, socket)
    broadcastOnlineStatus()

    socket.on('message', (rawData) => {
      let msg
      try { msg = JSON.parse(rawData.toString()) } catch { return }

      // ── P2P signaling relay (server never inspects payload) ──────────────
      if (msg.type === 'signal') {
        const { to, payload } = msg
        if (!to || typeof to !== 'string') return
        if (!payload || typeof payload !== 'object') return

        const recipient = stmts.findUser.get(to)
        if (!recipient) return

        const recipientWS = connections.get(recipient.id)
        if (recipientWS?.readyState === 1) {
          recipientWS.send(JSON.stringify({ type: 'signal', from: username, payload }))
        }
        return
      }

      // ── Server-stored message (offline fallback) ──────────────────────────
      if (msg.type === 'message') {
        const { to, ciphertext, iv } = msg

        // Validate fields
        if (!to || typeof to !== 'string') return
        if (!ciphertext || typeof ciphertext !== 'string' || ciphertext.length > 131072) return
        if (!iv || typeof iv !== 'string' || iv.length > 32) return

        const recipient = stmts.findUser.get(to)
        if (!recipient) return

        const result = stmts.insertMsg.run(userId, recipient.id, ciphertext, iv)

        const envelope = {
          type: 'message',
          id:   result.lastInsertRowid,
          from: username,
          ciphertext,
          iv,
          createdAt: Math.floor(Date.now() / 1000),
        }

        // Deliver to recipient if online
        const recipientWS = connections.get(recipient.id)
        if (recipientWS?.readyState === 1) {
          recipientWS.send(JSON.stringify(envelope))
        }

        // Echo confirmation to sender
        socket.send(JSON.stringify({ ...envelope, type: 'sent', to }))
      }
    })

    socket.on('close', () => {
      connections.delete(userId)
      broadcastOnlineStatus()
    })

    socket.on('error', () => connections.delete(userId))
  })
})

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = Number(process.env.PORT ?? 3000)
const HOST = process.env.HOST ?? '127.0.0.1'

try {
  await app.listen({ port: PORT, host: HOST })
  console.log(`msngr listening on http://${HOST}:${PORT}`)
} catch (err) {
  console.error(err)
  process.exit(1)
}
