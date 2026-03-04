/**
 * peer.js – WebRTC DataChannel manager
 *
 * The server is used only for signaling (SDP offer/answer + ICE candidates).
 * Once the DataChannel is open, all messages flow directly peer-to-peer –
 * the server never sees the content.
 *
 * Double encryption in transit:
 *   1. WebRTC DTLS-SRTP (mandatory, automatic)
 *   2. Our AES-256-GCM layer (from crypto.js) – keys never leave the client
 *
 * Fallback: if P2P fails or peer is offline, caller uses server storage.
 */
'use strict'

const Peer = (() => {
  // ── STUN servers (public, no-account, no-log) ──────────────────────────────
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ]

  // username → RTCPeerConnection
  const pcs = new Map()
  // username → RTCDataChannel
  const channels = new Map()
  // username → 'connecting' | 'open' | 'closed'
  const state = new Map()
  // username → Array<pending messages (sent before channel opened)>
  const pending = new Map()

  // Callbacks set by app.js
  let _onMessage    = null  // (envelope) → void
  let _sendSignal   = null  // (to, payload) → void  (via WebSocket)
  let _onStateChange = null // (username, state) → void
  let _onFileStart  = null  // (from, fileId, meta) → void
  let _onFileChunk  = null  // (from, fileId, received, total) → void
  let _onFileReady  = null  // (from, meta, iv, encryptedBuffer) → void

  // ── File transfer state ────────────────────────────────────────────────────
  const inFiles = new Map()  // `${from}:${fileId}` → transfer object
  const FILE_CHUNK = 64 * 1024  // 64 KB per chunk

  function init(onMessage, sendSignal, onStateChange, onFileStart, onFileChunk, onFileReady) {
    _onMessage    = onMessage
    _sendSignal   = sendSignal
    _onStateChange = onStateChange
    _onFileStart  = onFileStart
    _onFileChunk  = onFileChunk
    _onFileReady  = onFileReady
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Initiate connection to a peer (caller side). */
  async function connect(username) {
    if (state.get(username) === 'open') return
    if (state.get(username) === 'connecting') return

    _setState(username, 'connecting')
    const pc = _createPC(username)

    // Create DataChannel (only caller creates it)
    const dc = pc.createDataChannel('msngr', { ordered: true })
    _setupChannel(dc, username)

    const offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    _sendSignal(username, { type: 'offer', sdp: pc.localDescription })
  }

  /** Handle an incoming signaling message from the server. */
  async function handleSignal(from, payload) {
    const { type } = payload

    if (type === 'offer') {
      _setState(from, 'connecting')
      const pc = _createPC(from)

      // Receiver side: DataChannel arrives via ondatachannel
      pc.ondatachannel = ({ channel }) => _setupChannel(channel, from)

      await pc.setRemoteDescription(new RTCSessionDescription(payload))
      const answer = await pc.createAnswer()
      await pc.setLocalDescription(answer)
      _sendSignal(from, { type: 'answer', sdp: pc.localDescription })

    } else if (type === 'answer') {
      const pc = pcs.get(from)
      if (pc) await pc.setRemoteDescription(new RTCSessionDescription(payload))

    } else if (type === 'ice') {
      const pc = pcs.get(from)
      if (pc && payload.candidate) {
        try { await pc.addIceCandidate(new RTCIceCandidate(payload.candidate)) } catch { /* ignore stale */ }
      }
    }
  }

  /**
   * Send an already-encrypted message object to a peer.
   * @returns {boolean} true if sent via P2P, false if caller must use server fallback
   */
  function send(username, envelope) {
    const ch = channels.get(username)
    if (ch?.readyState === 'open') {
      try {
        ch.send(JSON.stringify(envelope))
        return true
      } catch { /* fall through */ }
    }

    // Queue if still connecting (will flush when channel opens)
    if (state.get(username) === 'connecting') {
      if (!pending.has(username)) pending.set(username, [])
      pending.get(username).push(envelope)
      return true  // optimistically true – will be flushed
    }

    return false  // caller must use server
  }

  /**
   * Send an encrypted file to a peer via DataChannel.
   * Caller must encrypt the ArrayBuffer first and pass {data: ArrayBuffer, iv: Uint8Array}.
   * @returns {boolean} false if channel not open
   */
  async function sendFile(username, meta, encryptedData, iv) {
    const ch = channels.get(username)
    if (ch?.readyState !== 'open') return false

    const fileId     = (Math.random() * 0xFFFFFFFF) >>> 0
    const totalChunks = Math.ceil(encryptedData.byteLength / FILE_CHUNK)
    const ivB64 = btoa(String.fromCharCode(...iv))

    // 1. Send metadata
    ch.send(JSON.stringify({ type: 'file-start', fileId, totalChunks, iv: ivB64, ...meta }))

    // 2. Send binary chunks: [4 bytes fileId BE][4 bytes chunkIdx BE][data]
    for (let i = 0; i < totalChunks; i++) {
      const slice  = encryptedData.slice(i * FILE_CHUNK, (i + 1) * FILE_CHUNK)
      const packet = new Uint8Array(8 + slice.byteLength)
      const view   = new DataView(packet.buffer)
      view.setUint32(0, fileId, false)
      view.setUint32(4, i, false)
      packet.set(new Uint8Array(slice), 8)
      ch.send(packet.buffer)
      // Yield every 8 chunks to keep the main thread responsive
      if (i % 8 === 7) await new Promise(r => setTimeout(r, 0))
    }

    // 3. Done signal
    ch.send(JSON.stringify({ type: 'file-end', fileId }))
    return true
  }

  /** Returns true if a DataChannel to this peer is open. */
  function isOpen(username) {
    return channels.get(username)?.readyState === 'open'
  }

  /** Close connection to a peer (e.g. on logout). */
  function close(username) {
    channels.get(username)?.close()
    pcs.get(username)?.close()
    channels.delete(username)
    pcs.delete(username)
    state.delete(username)
    pending.delete(username)
  }

  /** Close all connections. */
  function closeAll() {
    for (const u of [...pcs.keys()]) close(u)
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  function _createPC(username) {
    // Close stale connection if any
    if (pcs.has(username)) {
      pcs.get(username).close()
      pcs.delete(username)
      channels.delete(username)
    }

    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS })
    pcs.set(username, pc)

    // Trickle ICE
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) _sendSignal(username, { type: 'ice', candidate })
    }

    pc.onconnectionstatechange = () => {
      const s = pc.connectionState
      if (s === 'failed' || s === 'closed' || s === 'disconnected') {
        _setState(username, 'closed')
        pcs.delete(username)
        channels.delete(username)
        pending.delete(username)
      }
    }

    return pc
  }

  function _setupChannel(dc, username) {
    channels.set(username, dc)

    dc.onopen = () => {
      _setState(username, 'open')
      // Flush pending messages
      const queue = pending.get(username) ?? []
      pending.delete(username)
      for (const env of queue) {
        try { dc.send(JSON.stringify(env)) } catch { /* ignore */ }
      }
    }

    dc.onmessage = ({ data }) => {
      // Binary frame = file chunk
      if (data instanceof ArrayBuffer) {
        _handleFileChunk(username, data)
        return
      }
      try {
        const env = JSON.parse(data)
        if (env.type === 'file-start') {
          inFiles.set(`${username}:${env.fileId}`, {
            meta: { name: env.name, size: env.size, mime: env.mime },
            iv: env.iv,
            totalChunks: env.totalChunks,
            chunks: new Map(),
          })
          _onFileStart?.(username, env.fileId, { name: env.name, size: env.size, mime: env.mime })
        } else if (env.type === 'file-end') {
          _finalizeFile(username, env.fileId)
        } else if (env.ciphertext && env.iv) {
          _onMessage?.({ ...env, from: username })
        }
      } catch { /* ignore malformed */ }
    }

    dc.onclose = () => {
      channels.delete(username)
      _setState(username, 'closed')
    }

    dc.onerror = () => {
      channels.delete(username)
      _setState(username, 'closed')
    }
  }

  function _handleFileChunk(username, ab) {
    if (ab.byteLength < 8) return
    const view    = new DataView(ab)
    const fileId  = view.getUint32(0, false)
    const idx     = view.getUint32(4, false)
    const key     = `${username}:${fileId}`
    const transfer = inFiles.get(key)
    if (!transfer) return
    transfer.chunks.set(idx, new Uint8Array(ab.slice(8)))
    _onFileChunk?.(username, fileId, transfer.chunks.size, transfer.totalChunks)
  }

  function _finalizeFile(username, fileId) {
    const key      = `${username}:${fileId}`
    const transfer = inFiles.get(key)
    if (!transfer) return
    inFiles.delete(key)

    const { meta, iv, totalChunks, chunks } = transfer
    // Reassemble ordered chunks
    let totalLen = 0
    for (let i = 0; i < totalChunks; i++) {
      const c = chunks.get(i)
      if (!c) return  // missing chunk – drop
      totalLen += c.length
    }
    const buf = new Uint8Array(totalLen)
    let offset = 0
    for (let i = 0; i < totalChunks; i++) {
      buf.set(chunks.get(i), offset)
      offset += chunks.get(i).length
    }
    // Pass encrypted buffer + iv to app.js for decryption
    _onFileReady?.(username, meta, iv, buf.buffer)
  }

  function _setState(username, s) {
    state.set(username, s)
    _onStateChange?.(username, s)
  }

  return { init, connect, handleSignal, send, sendFile, isOpen, close, closeAll }
})()
