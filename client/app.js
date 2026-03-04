/**
 * msngr – SPA logic
 *
 * Session model:
 *   localStorage  – JWT token, wrapped private key, public key (b64)
 *   sessionStorage – password (cleared on tab close → forces unlock on new tab)
 *
 * E2E key flow:
 *   register → generate keypair → store wrapped privkey locally → send pubkey to server
 *   login    → if local key: unwrap with password; else: generate new keypair & update server
 *   message  → encrypt with ECDH shared key → P2P DataChannel if peer online,
 *              otherwise server-stored ciphertext (offline fallback)
 *
 * Transport layers:
 *   P2P path  : AES-256-GCM (our E2E) + DTLS (WebRTC mandatory) – server sees nothing
 *   Server path: AES-256-GCM ciphertext stored at rest – server cannot decrypt
 */
'use strict'

// ── Constants ──────────────────────────────────────────────────────────────────
const LS_TOKEN   = 'msngr:token'
const LS_USER    = 'msngr:username'
const LS_PRIVKEY = u => `msngr:privkey:${u}`
const LS_PUBKEY  = u => `msngr:pubkey:${u}`
const SS_PASS    = 'msngr:pass'

// ── State ──────────────────────────────────────────────────────────────────────
const S = {
  username:    null,
  token:       null,
  privateKey:  null,   // CryptoKey (ECDH private)
  currentChat: null,
  sharedKeys:  new Map(),  // username → CryptoKey
  theirPubKeys: new Map(), // username → CryptoKey
  messages:    new Map(),  // username → Array<MsgObj>
  users:       [],
  onlineUsers: new Set(),
  ws:          null,
  wsRetries:   0,
  wsTimer:     null,
}

// ── DOM helpers ────────────────────────────────────────────────────────────────
const $  = id  => document.getElementById(id)
const el = tag => document.createElement(tag)

function show(id) { $(id).hidden = false }
function hide(id) { $(id).hidden = true }

function setErr(id, msg) {
  const e = $(id)
  e.textContent = msg ?? ''
  e.hidden = !msg
}

function disableBtn(id, on = true) { $(id).disabled = on }

// ── Screens ────────────────────────────────────────────────────────────────────
function showAuth()   { hide('unlock-screen'); hide('app'); show('auth-screen') }
function showUnlock(username) {
  $('unlock-username').value = username
  hide('auth-screen'); hide('app'); show('unlock-screen')
}
function showApp() {
  hide('auth-screen'); hide('unlock-screen')
  $('my-username').textContent = S.username
  show('app')
  loadUsers()
  connectWS()
  // Init P2P layer – callbacks wired after WS is available
  Peer.init(
    _onP2PMessage,
    (to, payload) => S.ws?.readyState === 1 && S.ws.send(JSON.stringify({ type: 'signal', to, payload })),
    _onPeerState,
  )
}

// ── API helper ─────────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const res = await fetch('/api' + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(S.token ? { Authorization: `Bearer ${S.token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? 'Request failed')
  return data
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────
async function getSharedKey(username) {
  if (S.sharedKeys.has(username)) return S.sharedKeys.get(username)

  let theirPub = S.theirPubKeys.get(username)
  if (!theirPub) {
    const { publicKey } = await api('GET', `/users/${username}/key`)
    theirPub = await Crypto.importPublicKey(publicKey)
    S.theirPubKeys.set(username, theirPub)
  }
  const shared = await Crypto.deriveSharedKey(S.privateKey, theirPub)
  S.sharedKeys.set(username, shared)
  return shared
}

async function encryptFor(plaintext, username) {
  return Crypto.encrypt(plaintext, await getSharedKey(username))
}

async function decryptFrom(ciphertext, iv, username) {
  try {
    return await Crypto.decrypt(ciphertext, iv, await getSharedKey(username))
  } catch {
    return '[⚠ could not decrypt]'
  }
}

// ── Session management ─────────────────────────────────────────────────────────
async function setupSession(username, token, password) {
  S.token    = token
  S.username = username
  localStorage.setItem(LS_TOKEN, token)
  localStorage.setItem(LS_USER,  username)
  sessionStorage.setItem(SS_PASS, password)

  const stored = localStorage.getItem(LS_PRIVKEY(username))
  if (stored) {
    S.privateKey = await Crypto.unwrapPrivateKey(JSON.parse(stored), password)
  } else {
    // New device – generate fresh keypair, update server
    const kp         = await Crypto.generateKeyPair()
    const pubB64      = await Crypto.exportPublicKey(kp.publicKey)
    const wrapped     = await Crypto.wrapPrivateKey(kp.privateKey, password)
    S.privateKey = kp.privateKey
    localStorage.setItem(LS_PRIVKEY(username), JSON.stringify(wrapped))
    localStorage.setItem(LS_PUBKEY(username),  pubB64)
    await api('PUT', '/users/me/key', { publicKey: pubB64 })
  }
}

// ── Auth actions ───────────────────────────────────────────────────────────────
async function doRegister() {
  const username = $('reg-username').value.trim()
  const password = $('reg-password').value
  const confirm  = $('reg-password2').value
  setErr('auth-error', null)

  if (password !== confirm) return setErr('auth-error', 'Passwords do not match')

  disableBtn('btn-register')
  try {
    // Generate keypair first (may take a moment on slow devices)
    const kp     = await Crypto.generateKeyPair()
    const pubB64 = await Crypto.exportPublicKey(kp.publicKey)

    const { token } = await api('POST', '/register', { username, password, publicKey: pubB64 })

    // Persist private key locally (wrapped with password)
    const wrapped = await Crypto.wrapPrivateKey(kp.privateKey, password)
    localStorage.setItem(LS_PRIVKEY(username), JSON.stringify(wrapped))
    localStorage.setItem(LS_PUBKEY(username),  pubB64)

    S.token      = token
    S.username   = username
    S.privateKey = kp.privateKey
    localStorage.setItem(LS_TOKEN, token)
    localStorage.setItem(LS_USER,  username)
    sessionStorage.setItem(SS_PASS, password)

    showApp()
  } catch (e) {
    setErr('auth-error', e.message)
  } finally {
    disableBtn('btn-register', false)
  }
}

async function doLogin() {
  const username = $('login-username').value.trim()
  const password = $('login-password').value
  setErr('auth-error', null)
  disableBtn('btn-login')
  try {
    const { token } = await api('POST', '/login', { username, password })
    await setupSession(username, token, password)
    showApp()
  } catch (e) {
    setErr('auth-error', e.message)
  } finally {
    disableBtn('btn-login', false)
  }
}

async function doUnlock() {
  const username = $('unlock-username').value
  const password = $('unlock-password').value
  setErr('unlock-error', null)
  disableBtn('btn-unlock')
  try {
    // Validate password by unwrapping the private key
    const stored = localStorage.getItem(LS_PRIVKEY(username))
    if (!stored) throw new Error('No local key found – please log in again')
    S.privateKey = await Crypto.unwrapPrivateKey(JSON.parse(stored), password)
    S.token      = localStorage.getItem(LS_TOKEN)
    S.username   = username
    sessionStorage.setItem(SS_PASS, password)
    showApp()
  } catch (e) {
    setErr('unlock-error', 'Wrong password or key corrupted')
  } finally {
    disableBtn('btn-unlock', false)
  }
}

function doLogout() {
  Peer.closeAll()
  if (S.ws) { S.ws.close(); S.ws = null }
  clearTimeout(S.wsTimer)
  localStorage.removeItem(LS_TOKEN)
  sessionStorage.removeItem(SS_PASS)
  // Keep private key in localStorage so user can unlock later
  Object.assign(S, {
    username: null, token: null, privateKey: null,
    currentChat: null, sharedKeys: new Map(), theirPubKeys: new Map(),
    messages: new Map(), users: [], onlineUsers: new Set(), ws: null,
  })
  showAuth()
}

// ── User list ──────────────────────────────────────────────────────────────────
async function loadUsers() {
  try {
    S.users = await api('GET', '/users')
    renderUserList()
  } catch { /* ignore */ }
}

function renderUserList() {
  const list = $('user-list')
  list.innerHTML = ''

  if (!S.users.length) {
    const p = el('p')
    p.className = 'no-users'
    p.textContent = 'No other users yet'
    list.appendChild(p)
    return
  }

  for (const u of S.users) {
    const item = el('div')
    item.className = 'user-item' + (u === S.currentChat ? ' active' : '')
    item.dataset.u = u

    const avatar = el('div')
    avatar.className = 'avatar'
    avatar.textContent = u[0].toUpperCase()
    if (S.onlineUsers.has(u)) {
      const dot = el('div')
      dot.className = 'online-dot'
      avatar.appendChild(dot)
    }

    const name = el('span')
    name.className = 'user-name'
    name.textContent = u

    item.appendChild(avatar)
    item.appendChild(name)
    item.addEventListener('click', () => openChat(u))
    list.appendChild(item)
  }
}

// ── Chat ───────────────────────────────────────────────────────────────────────
async function openChat(username) {
  S.currentChat = username
  renderUserList()

  // Update header
  $('chat-username').textContent = username
  $('chat-avatar').textContent   = username[0].toUpperCase()
  $('chat-status').textContent   = S.onlineUsers.has(username) ? '● online' : ''
  $('chat-status').className     = 'status' + (S.onlineUsers.has(username) ? ' online' : '')

  hide('chat-placeholder')
  const area = $('chat-area')
  area.hidden = false
  area.style.display = 'flex'

  if (!S.messages.has(username)) {
    await loadHistory(username)
  }
  renderMessages()
  $('msg-input').focus()

  // Initiate P2P if peer is online and no channel open yet
  if (S.onlineUsers.has(username) && !Peer.isOpen(username)) {
    Peer.connect(username).catch(() => {/* fallback to server silently */})
  }
}

async function loadHistory(username) {
  try {
    const rows = await api('GET', `/messages/${username}`)
    const decrypted = await Promise.all(rows.map(async row => ({
      id:        row.id,
      from:      row.sender,
      text:      await decryptFrom(row.ciphertext, row.iv, username),
      createdAt: row.createdAt,
    })))
    S.messages.set(username, decrypted)
  } catch {
    S.messages.set(username, [])
  }
}

function renderMessages() {
  const container = $('messages')
  container.innerHTML = ''

  const msgs = S.messages.get(S.currentChat) ?? []

  if (!msgs.length) {
    const p = el('p')
    p.className = 'empty-chat'
    p.textContent = 'No messages yet – say hello!'
    container.appendChild(p)
    scrollBottom()
    return
  }

  let lastDate = null
  for (const msg of msgs) {
    const date = new Date(msg.createdAt * 1000)
    const dateStr = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    if (dateStr !== lastDate) {
      lastDate = dateStr
      const sep = el('div')
      sep.className = 'date-sep'
      sep.textContent = dateStr
      container.appendChild(sep)
    }
    container.appendChild(makeBubble(msg))
  }
  scrollBottom()
}

function makeBubble(msg) {
  const isMine = msg.from === S.username
  const wrap = el('div')
  wrap.className = 'msg ' + (isMine ? 'sent' : 'recv')
  wrap.dataset.id = msg.id

  const bubble = el('div')
  bubble.className = 'bubble'
  bubble.textContent = msg.text  // textContent → XSS-safe

  const time = el('div')
  time.className = 'msg-time'
  time.textContent = new Date(msg.createdAt * 1000).toLocaleTimeString(undefined, {
    hour: '2-digit', minute: '2-digit',
  })

  wrap.appendChild(bubble)
  wrap.appendChild(time)
  return wrap
}

function scrollBottom() {
  const msgs = $('messages')
  msgs.scrollTop = msgs.scrollHeight
}

async function sendMessage() {
  const input = $('msg-input')
  const text  = input.value.trim()
  if (!text || !S.currentChat) return

  input.value = ''
  disableBtn('btn-send')

  try {
    const { ciphertext, iv } = await encryptFor(text, S.currentChat)
    const peer = S.currentChat

    // Optimistic local echo (shown immediately, no round-trip wait)
    const localEntry = { id: null, from: S.username, text, createdAt: Math.floor(Date.now() / 1000) }
    _pushMessage(peer, localEntry)

    // Try P2P DataChannel first
    const sentP2P = Peer.send(peer, { from: S.username, ciphertext, iv })

    if (!sentP2P) {
      // Fallback: server stores ciphertext (offline delivery)
      if (S.ws?.readyState !== 1) throw new Error('Not connected')
      S.ws.send(JSON.stringify({ type: 'message', to: peer, ciphertext, iv }))
    }
    // Note: P2P path never stores on server – true serverless messaging
  } catch (e) {
    input.value = text   // restore on failure
    console.error('Send failed:', e.message)
  } finally {
    disableBtn('btn-send', false)
    input.focus()
  }
}

// ── WebSocket ──────────────────────────────────────────────────────────────────
function connectWS() {
  if (S.ws?.readyState === 0 || S.ws?.readyState === 1) return

  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${location.host}/ws?token=${S.token}`)
  S.ws = ws

  ws.addEventListener('open', () => {
    S.wsRetries = 0
    updateConnStatus(true)
  })

  ws.addEventListener('message', async ({ data }) => {
    let msg
    try { msg = JSON.parse(data) } catch { return }
    await handleWSMessage(msg)
  })

  ws.addEventListener('close', (ev) => {
    S.ws = null
    updateConnStatus(false)
    if (ev.code === 4001) return // auth failure – don't reconnect
    scheduleReconnect()
  })

  ws.addEventListener('error', () => { /* close will fire */ })
}

function scheduleReconnect() {
  clearTimeout(S.wsTimer)
  if (S.wsRetries >= 6) return
  const delay = Math.min(1000 * 2 ** S.wsRetries, 30_000)
  S.wsRetries++
  S.wsTimer = setTimeout(() => {
    if (S.token) connectWS()
  }, delay)
}

function updateConnStatus(online) {
  const el = $('conn-status')
  if (!el) return
  el.textContent = online ? '' : '⚠ disconnected'
  el.hidden = online
}

async function handleWSMessage(msg) {
  switch (msg.type) {
    case 'online': {
      S.onlineUsers = new Set(msg.users)
      renderUserList()
      if (S.currentChat) {
        const online = S.onlineUsers.has(S.currentChat)
        $('chat-status').textContent = online ? '● online' : ''
        $('chat-status').className   = 'status' + (online ? ' online' : '')
        // Auto-connect P2P when peer comes online in current chat
        if (online && !Peer.isOpen(S.currentChat)) {
          Peer.connect(S.currentChat).catch(() => {})
        }
      }
      break
    }

    // ── Signaling relay (for WebRTC handshake only – no message content) ──
    case 'signal': {
      await Peer.handleSignal(msg.from, msg.payload)
      break
    }

    // ── Server-stored message (offline fallback path) ─────────────────────
    case 'message': {
      const text = await decryptFrom(msg.ciphertext, msg.iv, msg.from)
      const entry = { id: msg.id, from: msg.from, text, createdAt: msg.createdAt }
      _pushMessage(msg.from, entry)
      break
    }

    case 'sent': {
      // Server echo for offline-fallback messages (P2P path has local echo)
      // Avoid duplicate: local echo was already pushed
      break
    }

    case 'error':
    case 'info':
      console.warn('[ws]', msg.message)
      break
  }
}

// ── P2P callbacks (called by Peer module) ──────────────────────────────────────

async function _onP2PMessage(env) {
  // env = { from, ciphertext, iv } – decrypt and display
  const text  = await decryptFrom(env.ciphertext, env.iv, env.from)
  const entry = { id: null, from: env.from, text, createdAt: Math.floor(Date.now() / 1000) }
  _pushMessage(env.from, entry)
}

function _onPeerState(username, peerState) {
  // Update the P2P indicator in the chat header when viewing that user
  if (S.currentChat !== username) return
  const badge = $('p2p-badge')
  if (!badge) return
  badge.hidden  = peerState !== 'open'
  badge.title   = peerState === 'open' ? 'P2P – messages bypass the server' : ''
}

function _pushMessage(peer, entry) {
  if (!S.messages.has(peer)) S.messages.set(peer, [])
  S.messages.get(peer).push(entry)

  if (S.currentChat === peer) {
    $('messages').appendChild(makeBubble(entry))
    scrollBottom()
    // Remove empty-state placeholder if present
    $('messages').querySelector('.empty-chat')?.remove()
  }
}

// ── Startup ────────────────────────────────────────────────────────────────────
async function init() {
  const token    = localStorage.getItem(LS_TOKEN)
  const username = localStorage.getItem(LS_USER)
  const password = sessionStorage.getItem(SS_PASS)

  if (token && username && password) {
    // Try to restore full session from sessionStorage password
    try {
      await setupSession(username, token, password)
      showApp()
      return
    } catch { /* fall through to unlock */ }
  }

  if (token && username) {
    // Token exists but no password in sessionStorage → unlock screen
    showUnlock(username)
    return
  }

  showAuth()
}

// ── Event listeners ────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Auth tabs
  $('tab-login-btn').addEventListener('click', () => {
    $('tab-login-btn').classList.add('active')
    $('tab-reg-btn').classList.remove('active')
    $('tab-login-form').hidden = false
    $('tab-reg-form').hidden   = true
    setErr('auth-error', null)
  })
  $('tab-reg-btn').addEventListener('click', () => {
    $('tab-reg-btn').classList.add('active')
    $('tab-login-btn').classList.remove('active')
    $('tab-reg-form').hidden   = false
    $('tab-login-form').hidden = true
    setErr('auth-error', null)
  })

  // Auth forms – submit on Enter
  const loginEnter = e => { if (e.key === 'Enter') doLogin() }
  $('login-username').addEventListener('keydown', loginEnter)
  $('login-password').addEventListener('keydown', loginEnter)
  $('btn-login').addEventListener('click', doLogin)

  const regEnter = e => { if (e.key === 'Enter') doRegister() }
  $('reg-username').addEventListener('keydown', regEnter)
  $('reg-password').addEventListener('keydown', regEnter)
  $('reg-password2').addEventListener('keydown', regEnter)
  $('btn-register').addEventListener('click', doRegister)

  // Unlock
  $('unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock() })
  $('btn-unlock').addEventListener('click', doUnlock)
  $('btn-switch-user').addEventListener('click', () => {
    localStorage.removeItem(LS_TOKEN)
    sessionStorage.removeItem(SS_PASS)
    showAuth()
  })

  // App
  $('btn-logout').addEventListener('click', doLogout)
  $('btn-send').addEventListener('click', sendMessage)
  $('msg-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() }
  })

  init()
})
