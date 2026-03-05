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
  username:     null,
  token:        null,
  privateKey:   null,   // CryptoKey (ECDH private)
  currentChat:  null,   // username (1-1 chat)
  currentGroup: null,   // group id (number)
  sharedKeys:   new Map(),  // username → CryptoKey
  theirPubKeys: new Map(),  // username → CryptoKey
  messages:     new Map(),  // username → Array<MsgObj>
  groups:       [],         // [{id, name, owner, members?}]
  groupMsgs:    new Map(),  // groupId → Array<MsgObj>
  groupPolls:   new Map(),  // groupId → Array<PollObj>
  users:        [],
  onlineUsers:  new Set(),
  ws:           null,
  wsRetries:    0,
  wsTimer:      null,
  pendingFile:  null,   // {file, previewUrl} – file queued for sending
  unread:       new Map(),  // key → count  (key = username or `g:${groupId}`)
  lastMsg:      new Map(),  // key → preview string
  typingTimers: new Map(),  // username → timer id
}

// ── Avatar color ───────────────────────────────────────────────────────────────
const AVATAR_COLORS = ['#1565c0','#00695c','#ad1457','#6a1b9a','#e65100','#0277bd','#2e7d32','#f57f17','#4e342e','#37474f']
function avatarColor(str) {
  let h = 0
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0
  return AVATAR_COLORS[Math.abs(h) % AVATAR_COLORS.length]
}

function setAvatarColor(el, name) {
  el.style.setProperty('--av-color', avatarColor(name))
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

function updateTitle() {
  let total = 0
  for (const v of S.unread.values()) total += v
  document.title = total > 0 ? `(${total}) msngr` : 'msngr'
}

function _pluralVotes(n) {
  const mod10 = n % 10, mod100 = n % 100
  if (mod10 === 1 && mod100 !== 11) return `${n} голос`
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return `${n} голоса`
  return `${n} голосов`
}

function _previewText(entry) {
  if (!entry) return ''
  if (entry.msgType === 'file') return entry.file?.name ? `📎 ${entry.file.name}` : '📎 Файл'
  return entry.text ?? ''
}

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
  loadGroups()
  connectWS()
  Peer.init(
    _onP2PMessage,
    (to, payload) => S.ws?.readyState === 1 && S.ws.send(JSON.stringify({ type: 'signal', to, payload })),
    _onPeerState,
    _onFileStart,
    _onFileChunk,
    _onFileReady,
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
    return '[⚠ не удалось расшифровать]'
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

  if (password !== confirm) return setErr('auth-error', 'Пароли не совпадают')

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
    if (!stored) throw new Error('Ключ не найден — войдите заново')
    S.privateKey = await Crypto.unwrapPrivateKey(JSON.parse(stored), password)
    S.token      = localStorage.getItem(LS_TOKEN)
    S.username   = username
    sessionStorage.setItem(SS_PASS, password)
    showApp()
  } catch (e) {
    setErr('unlock-error', 'Неверный пароль или ключ повреждён')
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
  // Evict all cached group keys so they can't be read after logout
  for (const g of S.groups) GroupMgr.evict(g.id)
  clearTimeout(_typingTimer); _typingActive = false
  for (const t of S.typingTimers.values()) clearTimeout(t)
  document.title = 'msngr'
  Object.assign(S, {
    username: null, token: null, privateKey: null,
    currentChat: null, currentGroup: null,
    sharedKeys: new Map(), theirPubKeys: new Map(),
    messages: new Map(), groups: [], groupMsgs: new Map(), groupPolls: new Map(),
    users: [], onlineUsers: new Set(), ws: null, pendingFile: null,
    unread: new Map(), lastMsg: new Map(), typingTimers: new Map(),
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

// ── Groups ─────────────────────────────────────────────────────────────────────
async function loadGroups() {
  try {
    S.groups = await api('GET', '/groups')
    renderGroupList()
  } catch { /* ignore */ }
}

async function openGroup(groupId) {
  S.currentChat  = null
  S.currentGroup = groupId
  const group = S.groups.find(g => g.id === groupId)
  if (!group) return

  // Header
  S.unread.delete(`g:${groupId}`)
  updateTitle()
  $('chat-username').textContent = group.name
  $('chat-avatar').textContent   = group.name[0].toUpperCase()
  setAvatarColor($('chat-avatar'), group.name)
  $('chat-status').textContent   = `${group.members?.length ?? '?'} участников`
  $('chat-status').className     = 'status'
  $('p2p-badge').hidden          = true
  $('btn-group-menu').hidden     = false
  $('btn-poll').hidden           = false

  hide('chat-placeholder')
  const area = $('chat-area')
  area.hidden = false
  area.style.display = 'flex'

  if (!S.groupMsgs.has(groupId)) await loadGroupHistory(groupId)
  if (!S.groupPolls.has(groupId)) await loadGroupPolls(groupId)

  renderGroupMessages()
  $('app').classList.add('chat-open')
  $('msg-input').focus()
}

async function loadGroupHistory(groupId) {
  try {
    const rows = await api('GET', `/groups/${groupId}/messages`)
    const msgs = await Promise.all(rows.map(async row => ({
      id:        row.id,
      from:      row.sender,
      msgType:   row.msg_type,
      text:      row.msg_type === 'text'
                   ? await GroupMgr.decryptMsg(row.ciphertext, row.iv, groupId, getSharedKey, api)
                   : null,
      file:      row.msg_type === 'file' && row.meta
                   ? await _decryptGroupFile(row.ciphertext, row.iv, row.meta, groupId)
                   : null,
      createdAt: row.created_at,
    })))
    S.groupMsgs.set(groupId, msgs)
    if (msgs.length) S.lastMsg.set(`g:${groupId}`, `${msgs[msgs.length-1].from}: ${_previewText(msgs[msgs.length-1])}`)
  } catch {
    S.groupMsgs.set(groupId, [])
  }
}

async function _decryptGroupFile(ciphertext, iv, meta, groupId) {
  try {
    const encBuf = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0)).buffer
    const ivBuf  = Uint8Array.from(atob(iv), c => c.charCodeAt(0))
    const ab     = await GroupMgr.decryptFile(encBuf, ivBuf, groupId, getSharedKey, api)
    const blob   = new Blob([ab], { type: meta.mime || 'application/octet-stream' })
    return { ...meta, url: URL.createObjectURL(blob) }
  } catch {
    return { ...meta, url: null }
  }
}

async function loadGroupPolls(groupId) {
  try {
    const polls = await api('GET', `/groups/${groupId}/polls`)
    S.groupPolls.set(groupId, polls)
  } catch {
    S.groupPolls.set(groupId, [])
  }
}

function renderGroupList() {
  const list = $('group-list')
  if (!list) return
  // Keep the "new group" button, clear the rest
  const btn = $('btn-new-group')
  list.innerHTML = ''
  if (btn) list.appendChild(btn)

  if (!S.groups.length) {
    const p = el('p'); p.className = 'no-users'; p.textContent = 'Групп пока нет'
    list.appendChild(p)
    return
  }
  for (const g of S.groups) {
    const item = el('div')
    item.className = 'user-item' + (g.id === S.currentGroup ? ' active' : '')
    const av = el('div'); av.className = 'avatar'; av.textContent = g.name[0].toUpperCase()
    setAvatarColor(av, g.name)

    const info = el('div'); info.className = 'user-item-info'
    const row  = el('div'); row.className  = 'user-item-row'
    const name = el('span'); name.className = 'user-name'; name.textContent = g.name
    row.appendChild(name)

    const unreadCount = S.unread.get(`g:${g.id}`) ?? 0
    if (unreadCount > 0) {
      const badge = el('span'); badge.className = 'badge'; badge.textContent = unreadCount > 99 ? '99+' : unreadCount
      row.appendChild(badge)
    }
    info.appendChild(row)

    const preview = S.lastMsg.get(`g:${g.id}`)
    if (preview) {
      const prev = el('div'); prev.className = 'user-preview'; prev.textContent = preview
      info.appendChild(prev)
    }

    item.appendChild(av); item.appendChild(info)
    item.addEventListener('click', () => openGroup(g.id))
    list.appendChild(item)
  }
}

function renderGroupMessages() {
  const container = $('messages')
  const groupId   = S.currentGroup
  const msgs      = S.groupMsgs.get(groupId) ?? []
  const polls     = S.groupPolls.get(groupId) ?? []

  // Interleave messages and polls by createdAt
  const items = [
    ...msgs.map(m => ({ kind: 'msg', data: m, ts: m.createdAt })),
    ...polls.map(p => ({ kind: 'poll', data: p, ts: p.created_at })),
  ].sort((a, b) => a.ts - b.ts)

  const frag = document.createDocumentFragment()
  if (!items.length) {
    const p = el('p'); p.className = 'empty-chat'; p.textContent = 'Сообщений нет — напишите первым!'
    frag.appendChild(p)
  } else {
    let lastDate = null
    for (const item of items) {
      const dateStr = new Date(item.ts * 1000).toLocaleDateString('ru-RU', { month: 'short', day: 'numeric' })
      if (dateStr !== lastDate) {
        lastDate = dateStr
        const sep = el('div'); sep.className = 'date-sep'; sep.textContent = dateStr
        frag.appendChild(sep)
      }
      frag.appendChild(item.kind === 'poll' ? makePollCard(item.data) : makeBubble(item.data))
    }
  }
  container.innerHTML = ''
  container.appendChild(frag)
  scrollBottom()
}

// ── Group creation ─────────────────────────────────────────────────────────────
function showGroupModal() {
  // Populate member checkboxes
  const list = $('gm-member-list')
  list.innerHTML = ''
  for (const u of S.users) {
    const label = el('label'); label.className = 'member-check'
    const cb = el('input'); cb.type = 'checkbox'; cb.value = u; cb.name = 'gm'
    label.appendChild(cb)
    const av = el('span'); av.className = 'avatar'; av.style.cssText = 'width:28px;height:28px;font-size:11px'
    av.textContent = u[0].toUpperCase()
    const nm = el('span'); nm.textContent = u
    label.appendChild(av); label.appendChild(nm)
    list.appendChild(label)
  }
  show('group-modal')
}

async function doCreateGroup() {
  const name = $('gm-name').value.trim()
  if (!name) { setErr('gm-error', 'Введите название группы'); return }
  const members = [...document.querySelectorAll('#gm-member-list input:checked')].map(cb => cb.value)

  disableBtn('btn-create-group')
  setErr('gm-error', null)
  try {
    const res = await GroupMgr.createGroup(name, members, getSharedKey, S.username, api)
    hide('group-modal')
    $('gm-name').value = ''
    S.groups.unshift({ id: res.id, name, owner: S.username })
    renderGroupList()
    switchTab('groups')
    openGroup(res.id)
  } catch (e) {
    setErr('gm-error', e.message)
  } finally {
    disableBtn('btn-create-group', false)
  }
}

// ── Poll creation ──────────────────────────────────────────────────────────────
function showPollModal() {
  $('poll-options').innerHTML = ''
  for (let i = 0; i < 2; i++) addPollOption()
  $('poll-question').value = ''
  $('poll-multi').checked  = false
  show('poll-modal')
}

function addPollOption() {
  const opts = $('poll-options')
  if (opts.children.length >= 8) return
  const row = el('div'); row.className = 'poll-opt-row'
  const inp = el('input'); inp.type = 'text'; inp.placeholder = `Вариант ${opts.children.length + 1}`
  inp.maxLength = 100; inp.style.marginBottom = '0'
  const rm = el('button'); rm.type = 'button'; rm.className = 'icon-btn'; rm.textContent = '×'
  rm.style.cssText = 'width:36px;height:36px;flex-shrink:0'
  rm.addEventListener('click', () => { if (opts.children.length > 2) opts.removeChild(row) })
  row.appendChild(inp); row.appendChild(rm)
  opts.appendChild(row)
}

async function doCreatePoll() {
  const question = $('poll-question').value.trim()
  const options  = [...document.querySelectorAll('#poll-options input')].map(i => i.value.trim()).filter(Boolean)
  const multi    = $('poll-multi').checked

  if (!question) { setErr('poll-error', 'Введите вопрос'); return }
  if (options.length < 2) { setErr('poll-error', 'Нужно минимум 2 варианта'); return }

  disableBtn('btn-create-poll')
  setErr('poll-error', null)
  try {
    const poll = await api('POST', `/groups/${S.currentGroup}/polls`, { question, options, multi })
    if (!S.groupPolls.has(S.currentGroup)) S.groupPolls.set(S.currentGroup, [])
    S.groupPolls.get(S.currentGroup).push(poll)
    hide('poll-modal')
    renderGroupMessages()
  } catch (e) {
    setErr('poll-error', e.message)
  } finally {
    disableBtn('btn-create-poll', false)
  }
}

async function votePoll(pollId, optionIdx) {
  try {
    const res = await api('POST', `/polls/${pollId}/vote`, { optionIdx })
    _updatePollVotes(pollId, res.votes)
  } catch { /* ignore */ }
}

function _updatePollVotes(pollId, votes) {
  for (const polls of S.groupPolls.values()) {
    const p = polls.find(p => p.id === pollId)
    if (p) { p.votes = votes; break }
  }
  // Re-render the poll card in DOM
  document.querySelectorAll(`.poll-card[data-id="${pollId}"]`).forEach(card => {
    const poll = [...S.groupPolls.values()].flat().find(p => p.id === pollId)
    if (poll) card.replaceWith(makePollCard(poll))
  })
}

function makePollCard(poll) {
  const options = Array.isArray(poll.options) ? poll.options : JSON.parse(poll.options)
  const totalVotes = poll.votes?.length ?? 0
  const isMine = poll.creator_id ? false : (poll.creator === S.username)

  const card = el('div')
  card.className = 'poll-card'
  card.dataset.id = poll.id

  const q = el('div'); q.className = 'poll-question'; q.textContent = '📊 ' + poll.question
  card.appendChild(q)

  const myVotes = new Set(poll.myVotes ?? [])

  for (let i = 0; i < options.length; i++) {
    const optVotes = poll.votes?.filter(v => v.option_idx === i).length ?? 0
    const pct      = totalVotes > 0 ? Math.round((optVotes / totalVotes) * 100) : 0
    const voted    = myVotes.has(i)

    const row = el('div'); row.className = 'poll-opt' + (voted ? ' voted' : '')
    const btn = el('button'); btn.className = 'poll-opt-btn'; btn.type = 'button'
    btn.textContent = options[i]
    btn.addEventListener('click', () => votePoll(poll.id, i))

    const bar = el('div'); bar.className = 'poll-bar'
    const fill = el('div'); fill.className = 'poll-fill'; fill.style.width = pct + '%'
    const pctLabel = el('span'); pctLabel.textContent = `${pct}% (${optVotes})`
    bar.appendChild(fill); bar.appendChild(pctLabel)

    row.appendChild(btn); row.appendChild(bar)
    card.appendChild(row)
  }

  const footer = el('div'); footer.className = 'poll-footer'
  footer.textContent = `${_pluralVotes(totalVotes)} · ${poll.multi ? 'несколько вариантов' : 'один вариант'}`
  card.appendChild(footer)

  return card
}

// ── Group info panel ───────────────────────────────────────────────────────────
async function showGroupInfo() {
  const gid   = S.currentGroup
  if (!gid) return
  const group = await api('GET', `/groups/${gid}`)
  // Update local members list
  const g = S.groups.find(x => x.id === gid)
  if (g) g.members = group.members
  // Update status text
  $('chat-status').textContent = `${group.members.length} участников`

  const list = $('group-info-members')
  list.innerHTML = ''
  for (const m of group.members) {
    const row = el('div'); row.className = 'gi-member'
    const av = el('div'); av.className = 'avatar'
    av.style.cssText = 'width:32px;height:32px;font-size:12px;flex-shrink:0'
    av.textContent = m.username[0].toUpperCase()
    if (S.onlineUsers.has(m.username)) {
      const dot = el('div'); dot.className = 'online-dot'; av.appendChild(dot)
    }
    const info = el('div'); info.style.flex = '1'
    const name = el('span'); name.textContent = m.username; name.style.fontWeight = '500'
    const role = el('span'); role.textContent = m.role; role.style.cssText = 'font-size:11px;color:var(--muted);margin-left:6px'
    info.appendChild(name); info.appendChild(role)

    row.appendChild(av); row.appendChild(info)

    // Remove button (owner/admin can remove members)
    if (group.owner === S.username && m.username !== S.username) {
      const rm = el('button'); rm.className = 'icon-btn'; rm.textContent = '×'
      rm.style.cssText = 'width:32px;height:32px;color:var(--error)'
      rm.addEventListener('click', async () => {
        if (!confirm(`Удалить ${m.username} из группы?`)) return
        try {
          await api('DELETE', `/groups/${gid}/members/${m.username}`)
          g.members = g.members.filter(x => x.username !== m.username)
          showGroupInfo()
        } catch (e) { alert(e.message) }
      })
      row.appendChild(rm)
    }
    list.appendChild(row)
  }
  $('group-info-name').textContent = group.name
  show('group-info-panel')
}

function renderUserList() {
  const list = $('user-list')
  list.innerHTML = ''

  if (!S.users.length) {
    const p = el('p')
    p.className = 'no-users'
    p.textContent = 'Других пользователей пока нет'
    list.appendChild(p)
    return
  }

  for (const u of S.users) {
    const item = el('div')
    item.className = 'user-item' + (u === S.currentChat ? ' active' : '')
    item.dataset.u = u

    const avatar = el('div')
    avatar.className = 'avatar'
    setAvatarColor(avatar, u)
    avatar.textContent = u[0].toUpperCase()
    if (S.onlineUsers.has(u)) {
      const dot = el('div')
      dot.className = 'online-dot'
      avatar.appendChild(dot)
    }

    const info = el('div'); info.className = 'user-item-info'
    const row  = el('div'); row.className  = 'user-item-row'
    const name = el('span'); name.className = 'user-name'; name.textContent = u
    row.appendChild(name)

    const unreadCount = S.unread.get(u) ?? 0
    if (unreadCount > 0) {
      const badge = el('span'); badge.className = 'badge'; badge.textContent = unreadCount > 99 ? '99+' : unreadCount
      row.appendChild(badge)
    }
    info.appendChild(row)

    const preview = S.lastMsg.get(u)
    if (preview) {
      const prev = el('div'); prev.className = 'user-preview'; prev.textContent = preview
      info.appendChild(prev)
    }

    item.appendChild(avatar)
    item.appendChild(info)
    item.addEventListener('click', () => openChat(u))
    list.appendChild(item)
  }
}

// ── Sidebar tab switching ──────────────────────────────────────────────────────
function switchTab(tab) {
  const isGroups = tab === 'groups'
  $('stab-chats').classList.toggle('active', !isGroups)
  $('stab-groups').classList.toggle('active', isGroups)
  $('user-list').hidden  = isGroups
  $('group-list').hidden = !isGroups
}

// ── Chat ───────────────────────────────────────────────────────────────────────
async function openChat(username) {
  S.currentChat  = username
  S.currentGroup = null
  S.unread.delete(username)
  updateTitle()
  $('btn-group-menu').hidden = true
  $('btn-poll').hidden       = true
  renderUserList()

  // Update header
  $('chat-username').textContent = username
  $('chat-avatar').textContent   = username[0].toUpperCase()
  setAvatarColor($('chat-avatar'), username)
  const online = S.onlineUsers.has(username)
  $('chat-status').textContent   = online ? '● online' : ''
  $('chat-status').className     = 'status' + (online ? ' online' : '')

  // Reset typing UI when switching chat
  const typingEl = $('typing-status')
  if (typingEl) typingEl.hidden = true
  _sendTyping(false)

  hide('chat-placeholder')
  const area = $('chat-area')
  area.hidden = false
  area.style.display = 'flex'

  if (!S.messages.has(username)) {
    await loadHistory(username)
  }
  renderMessages()
  $('msg-input').focus()

  // Mobile: slide to chat panel
  $('app').classList.add('chat-open')

  // Initiate P2P if peer is online and no channel open yet
  if (online && !Peer.isOpen(username)) {
    Peer.connect(username).catch(() => {/* fallback to server silently */})
  }
}

async function loadHistory(username) {
  try {
    const rows = await api('GET', `/messages/${username}`)
    const decrypted = await Promise.all(rows.map(async row => {
      if (row.msg_type === 'file' && row.meta) {
        const meta = typeof row.meta === 'string' ? JSON.parse(row.meta) : row.meta
        let file = { ...meta, url: null }
        try {
          const encBuf = Uint8Array.from(atob(row.ciphertext), c => c.charCodeAt(0)).buffer
          const ivBuf  = Uint8Array.from(atob(row.iv), c => c.charCodeAt(0))
          const ab     = await Crypto.decryptBinary(encBuf, ivBuf, await getSharedKey(username))
          file.url     = URL.createObjectURL(new Blob([ab], { type: meta.mime }))
        } catch { /* show without download link */ }
        return { id: row.id, from: row.sender, msgType: 'file', file, createdAt: row.createdAt }
      }
      return {
        id:        row.id,
        from:      row.sender,
        msgType:   'text',
        text:      await decryptFrom(row.ciphertext, row.iv, username),
        createdAt: row.createdAt,
      }
    }))
    S.messages.set(username, decrypted)
    if (decrypted.length) S.lastMsg.set(username, _previewText(decrypted[decrypted.length - 1]))
  } catch {
    S.messages.set(username, [])
  }
}

function renderMessages() {
  const container = $('messages')
  const msgs = S.messages.get(S.currentChat) ?? []

  // Single DOM write via DocumentFragment – avoids repeated reflows
  const frag = document.createDocumentFragment()

  if (!msgs.length) {
    const p = el('p')
    p.className = 'empty-chat'
    p.textContent = 'Сообщений нет — напишите первым!'
    frag.appendChild(p)
  } else {
    let lastDate = null
    for (const msg of msgs) {
      const date = new Date(msg.createdAt * 1000)
      const dateStr = date.toLocaleDateString('ru-RU', { month: 'short', day: 'numeric' })
      if (dateStr !== lastDate) {
        lastDate = dateStr
        const sep = el('div')
        sep.className = 'date-sep'
        sep.textContent = dateStr
        frag.appendChild(sep)
      }
      frag.appendChild(makeBubble(msg))
    }
  }

  container.innerHTML = ''
  container.appendChild(frag)
  scrollBottom()
}

function makeBubble(msg) {
  const isMine = msg.from === S.username
  const wrap   = el('div')
  wrap.className = 'msg ' + (isMine ? 'sent' : 'recv')
  if (msg.id) wrap.dataset.id = msg.id

  if (!isMine && (S.currentGroup || msg.groupId)) {
    const sender = el('div'); sender.className = 'msg-sender'; sender.textContent = msg.from
    wrap.appendChild(sender)
  }

  const bubble = el('div')
  bubble.className = 'bubble'

  if (msg.msgType === 'file' && msg.file) {
    bubble.appendChild(_makeFileCard(msg.file))
  } else {
    bubble.textContent = msg.text ?? ''
  }

  const time = el('div')
  time.className = 'msg-time'
  const timeStr = el('span')
  timeStr.textContent = new Date(msg.createdAt * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
  time.appendChild(timeStr)

  if (isMine) {
    const tick = el('span'); tick.className = 'tick'; tick.textContent = '✓'
    time.appendChild(tick)
  }

  wrap.appendChild(bubble)
  wrap.appendChild(time)
  return wrap
}

function _makeFileCard(file) {
  const card = el('div'); card.className = 'file-card'

  if (file.mime?.startsWith('image/') && file.url) {
    const img = el('img')
    img.src = file.url; img.className = 'file-img'; img.loading = 'lazy'
    img.alt = file.name
    card.appendChild(img)
  } else {
    const icon = el('span'); icon.className = 'file-icon'; icon.textContent = _fileIcon(file.mime)
    card.appendChild(icon)
  }

  const info = el('div'); info.className = 'file-info'
  const name = el('div'); name.className = 'file-name'; name.textContent = file.name
  const size = el('div'); size.className = 'file-size'; size.textContent = _fmtSize(file.size)
  info.appendChild(name); info.appendChild(size)
  card.appendChild(info)

  if (file.url) {
    const dl = el('a'); dl.href = file.url; dl.download = file.name
    dl.className = 'file-dl'; dl.textContent = '↓ Скачать'
    card.appendChild(dl)
  } else {
    const lbl = el('span'); lbl.className = 'file-dl'; lbl.style.opacity = '.4'; lbl.textContent = 'Получение…'
    card.appendChild(lbl)
  }
  return card
}

function _fileIcon(mime = '') {
  if (mime.startsWith('image/'))  return '🖼'
  if (mime.startsWith('video/'))  return '🎬'
  if (mime.startsWith('audio/'))  return '🎵'
  if (mime.includes('pdf'))       return '📄'
  if (mime.includes('zip') || mime.includes('tar') || mime.includes('gzip')) return '📦'
  if (mime.includes('word') || mime.includes('document')) return '📝'
  if (mime.includes('sheet') || mime.includes('excel'))   return '📊'
  if (mime.includes('presentation') || mime.includes('powerpoint')) return '📊'
  return '📁'
}

function _fmtSize(bytes) {
  if (!bytes) return ''
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 ** 2) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 ** 2).toFixed(1) + ' MB'
}

function scrollBottom() {
  const msgs = $('messages')
  // requestAnimationFrame ensures layout is complete before measuring
  requestAnimationFrame(() => { msgs.scrollTop = msgs.scrollHeight })
}

async function sendMessage() {
  const input = $('msg-input')
  const text  = input.value.trim()
  const file  = S.pendingFile?.file ?? null

  if (!text && !file) return
  if (!S.currentChat && !S.currentGroup) return

  input.value = ''
  clearPendingFile()
  disableBtn('btn-send')

  try {
    if (S.currentGroup) {
      await _sendGroupMessage(text, file)
    } else {
      await _send1to1Message(text, file)
    }
  } catch (e) {
    if (text) input.value = text
    console.error('Send failed:', e.message)
  } finally {
    disableBtn('btn-send', false)
    input.focus()
  }
}

async function _send1to1Message(text, file) {
  const peer = S.currentChat
  const now  = Math.floor(Date.now() / 1000)

  if (file) {
    const sharedKey = await getSharedKey(peer)
    const ab = await file.arrayBuffer()
    const { data: encData, iv } = await Crypto.encryptBinary(ab, sharedKey)
    const meta = { name: file.name, size: file.size, mime: file.type }

    // Local echo with object URL
    const blob = new Blob([ab], { type: file.type })
    const localEntry = { id: null, from: S.username, msgType: 'file', file: { ...meta, url: URL.createObjectURL(blob) }, createdAt: now }
    _pushMessage(peer, localEntry)

    // Try P2P first; otherwise encode for server
    const sentP2P = await Peer.sendFile(peer, meta, encData, iv)
    if (!sentP2P) {
      // Fallback: base64 encode and send via WS
      const ctB64 = btoa(String.fromCharCode(...new Uint8Array(encData)))
      const ivB64 = btoa(String.fromCharCode(...iv))
      if (S.ws?.readyState !== 1) throw new Error('Нет подключения')
      S.ws.send(JSON.stringify({ type: 'message', to: peer, ciphertext: ctB64, iv: ivB64, msgType: 'file', meta }))
    }
  } else {
    const { ciphertext, iv } = await encryptFor(text, peer)
    const localEntry = { id: null, from: S.username, msgType: 'text', text, createdAt: now }
    _pushMessage(peer, localEntry)

    const sentP2P = Peer.send(peer, { from: S.username, ciphertext, iv })
    if (!sentP2P) {
      if (S.ws?.readyState !== 1) throw new Error('Нет подключения')
      S.ws.send(JSON.stringify({ type: 'message', to: peer, ciphertext, iv }))
    }
  }
}

async function _sendGroupMessage(text, file) {
  const gid = S.currentGroup
  const now = Math.floor(Date.now() / 1000)

  if (file) {
    const { data: encData, iv } = await GroupMgr.encryptFile(await file.arrayBuffer(), gid, getSharedKey, api)
    const meta    = { name: file.name, size: file.size, mime: file.type }
    const ctB64   = btoa(String.fromCharCode(...new Uint8Array(encData)))
    const ivB64   = btoa(String.fromCharCode(...iv))

    const blob = new Blob([await file.arrayBuffer()], { type: file.type })
    const localEntry = { id: null, from: S.username, msgType: 'file', file: { ...meta, url: URL.createObjectURL(blob) }, createdAt: now }
    _pushGroupMessage(gid, localEntry)

    if (S.ws?.readyState !== 1) throw new Error('Нет подключения')
    S.ws.send(JSON.stringify({ type: 'group-message', groupId: gid, ciphertext: ctB64, iv: ivB64, msgType: 'file', meta }))
  } else {
    const { ciphertext, iv } = await GroupMgr.encryptMsg(text, gid, getSharedKey, api)
    const localEntry = { id: null, from: S.username, msgType: 'text', text, createdAt: now }
    _pushGroupMessage(gid, localEntry)

    if (S.ws?.readyState !== 1) throw new Error('Нет подключения')
    S.ws.send(JSON.stringify({ type: 'group-message', groupId: gid, ciphertext, iv }))
  }
}

// ── File attachment ────────────────────────────────────────────────────────────
function onFileSelected(file) {
  if (!file) return
  S.pendingFile = { file, previewUrl: file.type.startsWith('image/') ? URL.createObjectURL(file) : null }
  const preview = $('file-preview')
  const name    = $('file-preview-name')
  const thumb   = $('file-preview-thumb')
  name.textContent = file.name + ' (' + _fmtSize(file.size) + ')'
  if (thumb) {
    if (S.pendingFile.previewUrl) { thumb.src = S.pendingFile.previewUrl; thumb.hidden = false }
    else thumb.hidden = true
  }
  preview.hidden = false
  $('msg-input').placeholder = ''
}

function clearPendingFile() {
  if (S.pendingFile?.previewUrl) URL.revokeObjectURL(S.pendingFile.previewUrl)
  S.pendingFile = null
  const preview = $('file-preview'); if (preview) preview.hidden = true
  const thumb   = $('file-preview-thumb'); if (thumb) { thumb.hidden = true; thumb.src = '' }
  $('msg-input').placeholder = 'Сообщение…'
  $('file-input').value = ''
}

// ── WebSocket ──────────────────────────────────────────────────────────────────
function connectWS() {
  if (S.ws?.readyState === 0 || S.ws?.readyState === 1) return

  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${location.host}/ws`)
  S.ws = ws

  ws.addEventListener('open', () => {
    // Send auth token as first message (not in URL – avoids server logs)
    ws.send(JSON.stringify({ type: 'auth', token: S.token }))
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
  el.textContent = online ? '' : '⚠ нет связи'
  el.hidden = online
}

async function handleWSMessage(msg) {
  switch (msg.type) {
    case 'auth-ok': {
      S.wsRetries = 0
      updateConnStatus(true)
      break
    }

    case 'online': {
      S.onlineUsers = new Set(msg.users)
      renderUserList()
      if (S.currentChat) {
        const online = S.onlineUsers.has(S.currentChat)
        $('chat-status').textContent = online ? '● online' : ''
        $('chat-status').className   = 'status' + (online ? ' online' : '')
        if (online && !Peer.isOpen(S.currentChat)) Peer.connect(S.currentChat).catch(() => {})
      }
      break
    }

    case 'signal':
      await Peer.handleSignal(msg.from, msg.payload)
      break

    // ── 1-1 message (incoming, server-stored path) ────────────────────────
    case 'message': {
      let entry
      if (msg.msgType === 'file' && msg.meta) {
        let file = { ...msg.meta, url: null }
        try {
          const encBuf = Uint8Array.from(atob(msg.ciphertext), c => c.charCodeAt(0)).buffer
          const ivBuf  = Uint8Array.from(atob(msg.iv), c => c.charCodeAt(0))
          const ab     = await Crypto.decryptBinary(encBuf, ivBuf, await getSharedKey(msg.from))
          file.url     = URL.createObjectURL(new Blob([ab], { type: msg.meta.mime }))
        } catch { /* show without download */ }
        entry = { id: msg.id, from: msg.from, msgType: 'file', file, createdAt: msg.createdAt }
      } else {
        const text = await decryptFrom(msg.ciphertext, msg.iv, msg.from)
        entry = { id: msg.id, from: msg.from, msgType: 'text', text, createdAt: msg.createdAt }
      }
      _pushMessage(msg.from, entry)
      break
    }

    case 'sent':
      // Local echo already shown; nothing to do
      break

    // ── Group messages ────────────────────────────────────────────────────
    case 'group-message': {
      const gid = msg.groupId
      let entry
      if (msg.msgType === 'file' && msg.meta) {
        let file = { ...msg.meta, url: null }
        try {
          const encBuf = Uint8Array.from(atob(msg.ciphertext), c => c.charCodeAt(0)).buffer
          const ivBuf  = Uint8Array.from(atob(msg.iv), c => c.charCodeAt(0))
          const ab     = await GroupMgr.decryptFile(encBuf, ivBuf, gid, getSharedKey, api)
          file.url     = URL.createObjectURL(new Blob([ab], { type: msg.meta.mime }))
        } catch { /* show without download */ }
        entry = { id: msg.id, from: msg.from, msgType: 'file', file, createdAt: msg.createdAt }
      } else {
        const text = await GroupMgr.decryptMsg(msg.ciphertext, msg.iv, gid, getSharedKey, api)
        entry = { id: msg.id, from: msg.from, msgType: 'text', text, createdAt: msg.createdAt }
      }
      _pushGroupMessage(gid, entry)
      break
    }

    case 'group-sent':
      break  // local echo already pushed

    case 'group-added': {
      if (!S.groups.find(g => g.id === msg.group.id)) {
        S.groups.unshift(msg.group)
        renderGroupList()
      }
      break
    }

    case 'group-member-added':
    case 'group-member-removed': {
      // Refresh group if currently viewing it
      if (S.currentGroup === msg.groupId) loadGroupHistory(msg.groupId)
      break
    }

    case 'group-removed': {
      S.groups = S.groups.filter(g => g.id !== msg.groupId)
      renderGroupList()
      if (S.currentGroup === msg.groupId) {
        S.currentGroup = null
        hide('chat-area')
        show('chat-placeholder')
      }
      break
    }

    case 'group-poll': {
      const polls = S.groupPolls.get(msg.groupId)
      if (polls) polls.push(msg.poll)
      if (S.currentGroup === msg.groupId) renderGroupMessages()
      break
    }

    case 'poll-update': {
      _updatePollVotes(msg.pollId, msg.votes)
      break
    }

    case 'typing':
      _showTyping(msg.from, msg.isTyping)
      break

    case 'error':
    case 'info':
      console.warn('[ws]', msg.message)
      break
  }
}

// ── P2P callbacks (called by Peer module) ──────────────────────────────────────

async function _onP2PMessage(env) {
  const text  = await decryptFrom(env.ciphertext, env.iv, env.from)
  const entry = { id: null, from: env.from, msgType: 'text', text, createdAt: Math.floor(Date.now() / 1000) }
  _pushMessage(env.from, entry)
}

function _onPeerState(username, peerState) {
  if (S.currentChat !== username) return
  const badge = $('p2p-badge')
  if (!badge) return
  badge.hidden = peerState !== 'open'
  badge.title  = peerState === 'open' ? 'P2P — сообщения минуют сервер' : ''
}

function _onFileStart(from, fileId, meta) {
  // Placeholder bubble so the user sees something arriving
  const placeholder = { id: `file-${from}-${fileId}`, from, msgType: 'file',
    file: { ...meta, url: null }, createdAt: Math.floor(Date.now() / 1000) }
  _pushMessage(from, placeholder)
}

function _onFileChunk(_from, _fileId, received, total) {
  // Could update a progress bar here; skip for now (minimal)
}

async function _onFileReady(from, meta, ivB64, encryptedBuffer) {
  try {
    const sharedKey = await getSharedKey(from)
    const iv  = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0))
    const ab  = await Crypto.decryptBinary(encryptedBuffer, iv, sharedKey)
    const url = URL.createObjectURL(new Blob([ab], { type: meta.mime }))
    // Replace placeholder bubble in message list
    const msgs = S.messages.get(from) ?? []
    const placeholder = msgs.find(m => m.id === `file-${from}-undefined` || (m.msgType === 'file' && !m.file?.url && m.from === from))
    if (placeholder) {
      placeholder.file = { ...meta, url }
      // Refresh bubble in DOM
      if (S.currentChat === from) {
        const bubble = $('messages').querySelector(`[data-id="${placeholder.id}"]`)
        if (bubble) {
          const newBubble = makeBubble(placeholder)
          bubble.replaceWith(newBubble)
        }
      }
    } else {
      const entry = { id: null, from, msgType: 'file', file: { ...meta, url }, createdAt: Math.floor(Date.now() / 1000) }
      _pushMessage(from, entry)
    }
  } catch { /* decryption failed */ }
}

function _pushMessage(peer, entry) {
  if (!S.messages.has(peer)) S.messages.set(peer, [])
  S.messages.get(peer).push(entry)

  // Update last message preview in sidebar
  if (entry.from) S.lastMsg.set(peer, _previewText(entry))

  if (S.currentChat === peer) {
    $('messages').querySelector('.empty-chat')?.remove()
    $('messages').appendChild(makeBubble(entry))
    scrollBottom()
  } else if (entry.from !== S.username) {
    // Increment unread only for messages from others
    S.unread.set(peer, (S.unread.get(peer) ?? 0) + 1)
    updateTitle()
    renderUserList()
  }
}

function _pushGroupMessage(groupId, entry) {
  if (!S.groupMsgs.has(groupId)) S.groupMsgs.set(groupId, [])
  S.groupMsgs.get(groupId).push(entry)

  const key = `g:${groupId}`
  if (entry.from) S.lastMsg.set(key, `${entry.from}: ${_previewText(entry)}`)

  if (S.currentGroup === groupId) {
    $('messages').querySelector('.empty-chat')?.remove()
    $('messages').appendChild(makeBubble(entry))
    scrollBottom()
  } else if (entry.from !== S.username) {
    S.unread.set(key, (S.unread.get(key) ?? 0) + 1)
    updateTitle()
    renderGroupList()
  }
}

// ── Typing indicator ───────────────────────────────────────────────────────────
let _typingActive = false
let _typingTimer  = null

function _sendTyping(isTyping) {
  if (!S.currentChat || !S.ws || S.ws.readyState !== 1) return
  if (isTyping === _typingActive) return
  _typingActive = isTyping
  S.ws.send(JSON.stringify({ type: 'typing', to: S.currentChat, isTyping }))
}

function onMsgInputKey() {
  if (!S.currentChat) return
  _sendTyping(true)
  clearTimeout(_typingTimer)
  _typingTimer = setTimeout(() => _sendTyping(false), 3000)
}

function _showTyping(from, isTyping) {
  if (S.currentChat !== from) return
  const el = $('typing-status')
  if (!el) return
  // Clear any previous timer for this user
  clearTimeout(S.typingTimers.get(from))
  if (isTyping) {
    el.innerHTML = `<span style="color:var(--muted)">${from}</span>&nbsp;<div class="typing-dots"><span></span><span></span><span></span></div>`
    el.hidden = false
    S.typingTimers.set(from, setTimeout(() => {
      el.hidden = true
    }, 4000))
  } else {
    el.hidden = true
  }
}

// ── visualViewport: keep input above soft keyboard on iOS/Android ──────────────
function setupViewport() {
  if (!window.visualViewport) return
  let ticking = false
  const update = () => {
    if (ticking) return
    ticking = true
    requestAnimationFrame(() => {
      ticking = false
      const kb = Math.max(0, window.innerHeight - window.visualViewport.height - window.visualViewport.offsetTop)
      document.documentElement.style.setProperty('--kb', kb + 'px')
      // Scroll to bottom when keyboard opens so last message stays visible
      if (kb > 50 && S.currentChat) scrollBottom()
    })
  }
  window.visualViewport.addEventListener('resize', update, { passive: true })
  window.visualViewport.addEventListener('scroll', update, { passive: true })
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
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); _sendTyping(false); sendMessage() }
    else onMsgInputKey()
  })

  // Sidebar tabs
  $('stab-chats').addEventListener('click',  () => switchTab('chats'))
  $('stab-groups').addEventListener('click', () => switchTab('groups'))

  // New group
  $('btn-new-group').addEventListener('click', showGroupModal)
  $('btn-cancel-group').addEventListener('click', () => hide('group-modal'))
  $('btn-create-group').addEventListener('click', doCreateGroup)
  $('gm-name').addEventListener('keydown', e => { if (e.key === 'Enter') doCreateGroup() })

  // Poll
  $('btn-poll').addEventListener('click', showPollModal)
  $('btn-cancel-poll').addEventListener('click', () => hide('poll-modal'))
  $('btn-create-poll').addEventListener('click', doCreatePoll)
  $('btn-add-poll-opt').addEventListener('click', addPollOption)

  // Group info
  $('btn-group-menu').addEventListener('click', showGroupInfo)
  $('btn-close-group-info').addEventListener('click', () => hide('group-info-panel'))

  // File attachment
  $('file-input').addEventListener('change', e => {
    const f = e.target.files?.[0]
    if (f) onFileSelected(f)
  })
  $('btn-cancel-file').addEventListener('click', clearPendingFile)

  // Mobile back button
  $('btn-back').addEventListener('click', () => {
    $('app').classList.remove('chat-open')
    S.currentChat  = null
    S.currentGroup = null
    hide('group-info-panel')
  })

  setupViewport()
  init()
})
