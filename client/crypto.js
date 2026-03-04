/**
 * msngr – client-side E2E encryption
 *
 * Scheme:
 *   • Key agreement : ECDH  P-256
 *   • Message enc   : AES-256-GCM  (12-byte random IV per message)
 *   • Key wrapping  : PBKDF2-SHA-256 → AES-256-GCM
 *                     (600 000 iterations, 16-byte random salt, 12-byte IV)
 *
 * The server stores only ciphertext + IV; plaintext never leaves the browser.
 */
'use strict'

const Crypto = (() => {
  const subtle = crypto.subtle

  // ── Key generation ──────────────────────────────────────────────────────────

  /** Generate an ECDH P-256 key pair (extractable). */
  async function generateKeyPair() {
    return subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,          // extractable (needed for wrapping / export)
      ['deriveKey'],
    )
  }

  // ── Key import / export ─────────────────────────────────────────────────────

  /** Export public key as base64-encoded uncompressed point (65 bytes → ~88 b64 chars). */
  async function exportPublicKey(publicKey) {
    const raw = await subtle.exportKey('raw', publicKey)
    return _b64(raw)
  }

  /** Import a base64 public key for ECDH key agreement. */
  async function importPublicKey(b64) {
    return subtle.importKey(
      'raw', _ub64(b64),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,         // public keys don't need to be extractable
      [],            // no usages on public key itself
    )
  }

  // ── Shared key derivation ───────────────────────────────────────────────────

  /**
   * Derive a shared AES-256-GCM key from my private key + their public key.
   * Both sides get the same key – ECDH is commutative.
   */
  async function deriveSharedKey(myPrivateKey, theirPublicKey) {
    return subtle.deriveKey(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )
  }

  // ── Message encrypt / decrypt ───────────────────────────────────────────────

  /** Encrypt a UTF-8 string. Returns { ciphertext, iv } as base64 strings. */
  async function encrypt(plaintext, sharedKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const data = new TextEncoder().encode(plaintext)
    const buf = await subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, data)
    return { ciphertext: _b64(buf), iv: _b64(iv) }
  }

  /** Decrypt base64 ciphertext + iv. Returns UTF-8 plaintext string. */
  async function decrypt(ciphertextB64, ivB64, sharedKey) {
    const buf = await subtle.decrypt(
      { name: 'AES-GCM', iv: _ub64(ivB64) },
      sharedKey,
      _ub64(ciphertextB64),
    )
    return new TextDecoder().decode(buf)
  }

  // ── Private key wrapping (localStorage protection) ─────────────────────────

  /**
   * Wrap (encrypt) the ECDH private key with a password-derived key.
   * Returns { wrapped, salt, iv } – all base64.  Safe to store in localStorage.
   */
  async function wrapPrivateKey(privateKey, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const iv   = crypto.getRandomValues(new Uint8Array(12))
    const wk   = await _deriveWrapKey(password, salt, ['wrapKey'])
    const buf  = await subtle.wrapKey('jwk', privateKey, wk, { name: 'AES-GCM', iv })
    return { wrapped: _b64(buf), salt: _b64(salt), iv: _b64(iv) }
  }

  /**
   * Unwrap the ECDH private key.  Throws DOMException if the password is wrong.
   */
  async function unwrapPrivateKey(stored, password) {
    const { wrapped, salt, iv } = stored
    const wk = await _deriveWrapKey(password, _ub64(salt), ['unwrapKey'])
    return subtle.unwrapKey(
      'jwk', _ub64(wrapped), wk,
      { name: 'AES-GCM', iv: _ub64(iv) },
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey'],
    )
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  async function _deriveWrapKey(password, salt, usages) {
    const raw = new TextEncoder().encode(password)
    const base = await subtle.importKey('raw', raw, 'PBKDF2', false, ['deriveKey'])
    return subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      usages,
    )
  }

  /** ArrayBuffer / TypedArray → base64 string */
  function _b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
  }

  /** base64 string → Uint8Array */
  function _ub64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  }

  return { generateKeyPair, exportPublicKey, importPublicKey, deriveSharedKey, encrypt, decrypt, wrapPrivateKey, unwrapPrivateKey }
})()
