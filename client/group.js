/**
 * group.js – Group key management
 *
 * Each group has one symmetric AES-256-GCM key shared by all members.
 * The key is never sent in plaintext – it is encrypted for each member via
 * their ECDH shared key with the key's grantor (usually the admin who invited them).
 *
 * Storage: keys are cached in memory (S.groupKeys). On page reload they are
 * re-fetched from the server and decrypted on demand.
 */
'use strict'

const GroupMgr = (() => {
  // groupId (number) → CryptoKey
  const cache = new Map()

  /**
   * Create a new group.
   * Generates a fresh group key, encrypts it for each member (via ECDH shared key),
   * then POSTs to the server.
   *
   * @param {string}   name         - Group display name
   * @param {string[]} memberNames  - Array of usernames to add (not including self)
   * @param {Function} getSharedKey - async (username) → CryptoKey  (ECDH, from app.js)
   * @param {string}   myUsername   - Current user's username
   * @param {Function} apiFn        - async (method, path, body) → response
   * @returns {Promise<{id: number}>}
   */
  async function createGroup(name, memberNames, getSharedKey, myUsername, apiFn) {
    const groupKey    = await Crypto.generateGroupKey()
    const groupKeyB64 = await Crypto.exportGroupKey(groupKey)

    const allMembers = [...new Set([myUsername, ...memberNames])]
    const groupKeys  = {}

    for (const username of allMembers) {
      const sharedKey       = await getSharedKey(username)
      const { ciphertext, iv } = await Crypto.encrypt(groupKeyB64, sharedKey)
      groupKeys[username]   = { ciphertext, iv }
    }

    const res = await apiFn('POST', '/groups', { name, members: memberNames, groupKeys })
    cache.set(res.id, groupKey)
    return res
  }

  /**
   * Get the decrypted group key (fetches from server on cache miss).
   *
   * @param {number}   groupId      - Group id
   * @param {Function} getSharedKey - async (username) → CryptoKey
   * @param {Function} apiFn        - async (method, path) → response
   * @returns {Promise<CryptoKey>}
   */
  async function getKey(groupId, getSharedKey, apiFn) {
    if (cache.has(groupId)) return cache.get(groupId)

    const row        = await apiFn('GET', `/groups/${groupId}/key`)
    const sharedKey  = await getSharedKey(row.grantor)
    const groupKeyB64 = await Crypto.decrypt(row.ciphertext, row.iv, sharedKey)
    const key         = await Crypto.importGroupKey(groupKeyB64)
    cache.set(groupId, key)
    return key
  }

  /**
   * Encrypt a group message.
   * @returns {Promise<{ciphertext: string, iv: string}>}
   */
  async function encryptMsg(plaintext, groupId, getSharedKey, apiFn) {
    const key = await getKey(groupId, getSharedKey, apiFn)
    return Crypto.encrypt(plaintext, key)
  }

  /**
   * Decrypt a group message.
   * @returns {Promise<string>}
   */
  async function decryptMsg(ciphertext, iv, groupId, getSharedKey, apiFn) {
    try {
      const key = await getKey(groupId, getSharedKey, apiFn)
      return Crypto.decrypt(ciphertext, iv, key)
    } catch {
      return '[⚠ could not decrypt]'
    }
  }

  /**
   * Encrypt a binary file for a group.
   * @returns {Promise<{data: ArrayBuffer, iv: Uint8Array}>}
   */
  async function encryptFile(arrayBuffer, groupId, getSharedKey, apiFn) {
    const key = await getKey(groupId, getSharedKey, apiFn)
    return Crypto.encryptBinary(arrayBuffer, key)
  }

  /**
   * Decrypt a binary file from a group.
   * @returns {Promise<ArrayBuffer>}
   */
  async function decryptFile(dataBuffer, iv, groupId, getSharedKey, apiFn) {
    const key = await getKey(groupId, getSharedKey, apiFn)
    return Crypto.decryptBinary(dataBuffer, iv, key)
  }

  /** Store a key directly (e.g. after creating a group – key already in memory). */
  function setKey(groupId, key) {
    cache.set(groupId, key)
  }

  /** Remove from cache (e.g. on member removal / key rotation). */
  function evict(groupId) {
    cache.delete(groupId)
  }

  return { createGroup, getKey, encryptMsg, decryptMsg, encryptFile, decryptFile, setKey, evict }
})()
