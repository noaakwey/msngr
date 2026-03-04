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
  let _onMessage   = null  // (from, text, createdAt) → void
  let _sendSignal  = null  // (to, payload) → void  (via WebSocket)
  let _onStateChange = null // (username, state) → void

  function init(onMessage, sendSignal, onStateChange) {
    _onMessage    = onMessage
    _sendSignal   = sendSignal
    _onStateChange = onStateChange
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
      try {
        const env = JSON.parse(data)
        if (_onMessage && env.ciphertext && env.iv && env.from) {
          _onMessage(env)  // already-encrypted envelope – app.js decrypts
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

  function _setState(username, s) {
    state.set(username, s)
    _onStateChange?.(username, s)
  }

  return { init, connect, handleSignal, send, isOpen, close, closeAll }
})()
