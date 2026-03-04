import Database from 'better-sqlite3'
import { mkdirSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const dataDir = join(__dirname, '../data')
mkdirSync(dataDir, { recursive: true })

const db = new Database(join(dataDir, 'msngr.db'))

db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')
db.pragma('synchronous = NORMAL')
db.pragma('temp_store = MEMORY')
db.pragma('mmap_size = 268435456')

// ── Core tables ────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    public_key    TEXT    NOT NULL,
    created_at    INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    msg_type     TEXT    NOT NULL DEFAULT 'text',
    ciphertext   TEXT    NOT NULL,
    iv           TEXT    NOT NULL,
    meta         TEXT,
    created_at   INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_msg_pair
    ON messages(min(sender_id, recipient_id), max(sender_id, recipient_id), created_at);
`)

// Migrate existing DB (idempotent: ADD COLUMN fails silently if column exists)
for (const sql of [
  `ALTER TABLE messages ADD COLUMN msg_type TEXT NOT NULL DEFAULT 'text'`,
  `ALTER TABLE messages ADD COLUMN meta TEXT`,
]) { try { db.exec(sql) } catch { /* already exists */ } }

// ── Group tables ───────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL CHECK(length(name) BETWEEN 1 AND 50),
    owner_id   INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT    NOT NULL DEFAULT 'member', -- 'owner' | 'admin' | 'member'
    joined_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (group_id, user_id)
  );

  -- Symmetric group key (AES-256-GCM), encrypted per-member via ECDH shared key
  CREATE TABLE IF NOT EXISTS group_keys (
    group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantor    TEXT    NOT NULL,  -- username of who encrypted the key for this user
    ciphertext TEXT    NOT NULL,
    iv         TEXT    NOT NULL,
    PRIMARY KEY (group_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS group_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    sender_id  INTEGER NOT NULL REFERENCES users(id),
    msg_type   TEXT    NOT NULL DEFAULT 'text', -- 'text' | 'file'
    ciphertext TEXT    NOT NULL CHECK(length(ciphertext) <= 5500000),
    iv         TEXT    NOT NULL,
    meta       TEXT,   -- JSON: {name, size, mime} for files
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_gm_group
    ON group_messages(group_id, created_at, id);

  -- Polls are plaintext (public within group, server counts votes)
  CREATE TABLE IF NOT EXISTS group_polls (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    creator_id INTEGER NOT NULL REFERENCES users(id),
    question   TEXT    NOT NULL CHECK(length(question) BETWEEN 1 AND 500),
    options    TEXT    NOT NULL,  -- JSON array, 2–8 options
    multi      INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS group_poll_votes (
    poll_id    INTEGER NOT NULL REFERENCES group_polls(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    option_idx INTEGER NOT NULL,
    PRIMARY KEY (poll_id, user_id, option_idx)
  );
`)

export const stmts = {
  // ── Users ──────────────────────────────────────────────────────────────────
  insertUser:    db.prepare('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)'),
  findUser:      db.prepare('SELECT id, username, password_hash, public_key FROM users WHERE username = ?'),
  updatePubKey:  db.prepare('UPDATE users SET public_key = ? WHERE id = ?'),
  listUsers:     db.prepare('SELECT username FROM users WHERE id != ? ORDER BY username'),
  userPubKey:    db.prepare('SELECT public_key FROM users WHERE username = ?'),

  // ── 1-1 Messages ──────────────────────────────────────────────────────────
  insertMsg: db.prepare(
    `INSERT INTO messages (sender_id, recipient_id, msg_type, ciphertext, iv, meta) VALUES (?, ?, ?, ?, ?, ?)`
  ),
  conversation: db.prepare(`
    SELECT m.id, u.username AS sender, m.msg_type, m.ciphertext, m.iv, m.meta,
           m.created_at AS createdAt
    FROM   messages m
    JOIN   users u ON u.id = m.sender_id
    WHERE  (m.sender_id = ? AND m.recipient_id = ?)
        OR (m.sender_id = ? AND m.recipient_id = ?)
    ORDER  BY m.created_at ASC, m.id ASC
    LIMIT  200
  `),

  // ── Groups ─────────────────────────────────────────────────────────────────
  createGroup:  db.prepare(`INSERT INTO groups (name, owner_id) VALUES (?, ?) RETURNING id`),
  findGroup:    db.prepare(`SELECT * FROM groups WHERE id = ?`),
  listMyGroups: db.prepare(`
    SELECT g.id, g.name, g.owner_id, g.created_at,
           (SELECT username FROM users WHERE id = g.owner_id) AS owner
    FROM groups g
    JOIN group_members gm ON gm.group_id = g.id
    WHERE gm.user_id = ?
    ORDER BY g.created_at DESC
  `),
  addMember:    db.prepare(`INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)`),
  removeMember: db.prepare(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`),
  groupMembers: db.prepare(`
    SELECT u.username, gm.role, gm.joined_at
    FROM group_members gm
    JOIN users u ON u.id = gm.user_id
    WHERE gm.group_id = ?
    ORDER BY CASE gm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, gm.joined_at ASC
  `),
  memberIds:    db.prepare(`SELECT user_id FROM group_members WHERE group_id = ?`),
  isMember:     db.prepare(`SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?`),
  memberRole:   db.prepare(`SELECT role FROM group_members WHERE group_id = ? AND user_id = ?`),
  memberCount:  db.prepare(`SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?`),

  setGroupKey: db.prepare(
    `INSERT OR REPLACE INTO group_keys (group_id, user_id, grantor, ciphertext, iv) VALUES (?, ?, ?, ?, ?)`
  ),
  getGroupKey: db.prepare(
    `SELECT grantor, ciphertext, iv FROM group_keys WHERE group_id = ? AND user_id = ?`
  ),

  insertGroupMsg: db.prepare(`
    INSERT INTO group_messages (group_id, sender_id, msg_type, ciphertext, iv, meta)
    VALUES (?, ?, ?, ?, ?, ?) RETURNING id, created_at
  `),
  groupMessages: db.prepare(`
    SELECT gm.id, gm.msg_type, gm.ciphertext, gm.iv, gm.meta, gm.created_at,
           u.username AS sender
    FROM group_messages gm
    JOIN users u ON u.id = gm.sender_id
    WHERE gm.group_id = ?
    ORDER BY gm.created_at ASC, gm.id ASC
    LIMIT 200
  `),

  // ── Polls ──────────────────────────────────────────────────────────────────
  createPoll:   db.prepare(`
    INSERT INTO group_polls (group_id, creator_id, question, options, multi)
    VALUES (?, ?, ?, ?, ?) RETURNING id, created_at
  `),
  groupPolls:   db.prepare(`SELECT * FROM group_polls WHERE group_id = ? ORDER BY created_at ASC`),
  getPoll:      db.prepare(`SELECT * FROM group_polls WHERE id = ?`),
  pollGroupId:  db.prepare(`SELECT group_id FROM group_polls WHERE id = ?`),
  addVote:      db.prepare(`INSERT OR IGNORE INTO group_poll_votes (poll_id, user_id, option_idx) VALUES (?, ?, ?)`),
  removeVote:   db.prepare(`DELETE FROM group_poll_votes WHERE poll_id = ? AND user_id = ? AND option_idx = ?`),
  clearVotes:   db.prepare(`DELETE FROM group_poll_votes WHERE poll_id = ? AND user_id = ?`),
  pollVotes:    db.prepare(`
    SELECT v.option_idx, u.username
    FROM group_poll_votes v
    JOIN users u ON u.id = v.user_id
    WHERE v.poll_id = ?
  `),
  userVotes:    db.prepare(`SELECT option_idx FROM group_poll_votes WHERE poll_id = ? AND user_id = ?`),
}

export default db
