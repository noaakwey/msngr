'use strict'
/**
 * Biometric unlock via WebAuthn PRF extension.
 *
 * Flow:
 *   setup(username, password)
 *     → creates a platform credential (Face ID / Touch ID / Windows Hello)
 *     → PRF output (HMAC from authenticator) is used as AES-256-GCM key
 *     → password is encrypted with that key and stored in localStorage
 *
 *   unlock(username)
 *     → triggers biometric prompt
 *     → same PRF output → decrypt stored password → return it
 *
 * No server involvement. Security relies on the platform authenticator
 * binding PRF output to this origin + user verification.
 */

const _RP_ID  = location.hostname || 'localhost'
const _PRF_IN = new TextEncoder().encode('msngr-unlock-v1')  // fixed PRF salt
const _LS_KEY = u => `msngr:bio:${u}`

/** True if a platform authenticator with user-verification is available. */
async function bioAvailable() {
  try {
    if (!window.PublicKeyCredential) return false
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch { return false }
}

/** True if biometric data is already stored for this username. */
function bioStored(username) {
  return !!localStorage.getItem(_LS_KEY(username))
}

/**
 * Register a new credential for this user and encrypt their password with
 * the PRF output. Throws if biometric is cancelled or PRF unsupported.
 */
async function bioSetup(username, password) {
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const uid       = crypto.getRandomValues(new Uint8Array(16))

  let cred
  try {
    cred = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { id: _RP_ID, name: 'msngr' },
        user: { id: uid, name: username, displayName: username },
        pubKeyCredParams: [
          { alg: -7,   type: 'public-key' },  // ES256  (most platforms)
          { alg: -257, type: 'public-key' },  // RS256  (Windows Hello fallback)
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        extensions: { prf: { eval: { first: _PRF_IN } } },
      },
    })
  } catch (e) {
    if (e.name === 'NotAllowedError') throw new Error('Отменено пользователем')
    throw new Error('Биометрия недоступна на этом устройстве')
  }

  const prfOut = cred.getClientExtensionResults()?.prf?.results?.first
  if (!prfOut) {
    throw new Error(
      'Устройство не поддерживает шифрование через биометрию (нужен PRF).\n' +
      'Попробуйте Chrome 108+ или Safari 16.4+.',
    )
  }

  // Encrypt password with PRF-derived AES key
  const aesKey = await crypto.subtle.importKey('raw', prfOut, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv     = crypto.getRandomValues(new Uint8Array(12))
  const ct     = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(password),
  )

  localStorage.setItem(_LS_KEY(username), JSON.stringify({
    credId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
    iv:     btoa(String.fromCharCode(...iv)),
    ct:     btoa(String.fromCharCode(...new Uint8Array(ct))),
  }))
}

/**
 * Trigger biometric prompt; decrypt and return the stored password.
 * Throws if cancelled, unsupported, or data corrupt.
 */
async function bioUnlock(username) {
  const raw = localStorage.getItem(_LS_KEY(username))
  if (!raw) throw new Error('Биометрия не настроена')

  const { credId, iv, ct } = JSON.parse(raw)
  const credIdBytes = Uint8Array.from(atob(credId), c => c.charCodeAt(0))
  const challenge   = crypto.getRandomValues(new Uint8Array(32))

  let assertion
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{ type: 'public-key', id: credIdBytes }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: _PRF_IN } } },
      },
    })
  } catch (e) {
    if (e.name === 'NotAllowedError') throw new Error('Отменено пользователем')
    throw new Error('Ошибка биометрии')
  }

  const prfOut = assertion.getClientExtensionResults()?.prf?.results?.first
  if (!prfOut) throw new Error('PRF недоступен — введите пароль')

  const aesKey   = await crypto.subtle.importKey('raw', prfOut, { name: 'AES-GCM' }, false, ['decrypt'])
  const ivBytes  = Uint8Array.from(atob(iv), c => c.charCodeAt(0))
  const ctBytes  = Uint8Array.from(atob(ct), c => c.charCodeAt(0))
  const passBytes = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, aesKey, ctBytes)
  return new TextDecoder().decode(passBytes)
}

/** Remove stored biometric data for this username. */
function bioClear(username) {
  localStorage.removeItem(_LS_KEY(username))
}

const Bio = { available: bioAvailable, stored: bioStored, setup: bioSetup, unlock: bioUnlock, clear: bioClear }
