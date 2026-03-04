import Database from 'better-sqlite3'
import { mkdirSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const dataDir = join(__dirname, '../data')
mkdirSync(dataDir, { recursive: true })

const db = new Database(join(dataDir, 'msngr.db'))

// Performance and integrity pragmas
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')
db.pragma('synchronous = NORMAL')
db.pragma('temp_store = MEMORY')
db.pragma('mmap_size = 268435456') // 256 MB

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
    ciphertext   TEXT    NOT NULL,
    iv           TEXT    NOT NULL,
    created_at   INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_msg_pair
    ON messages(min(sender_id, recipient_id), max(sender_id, recipient_id), created_at);
`)

// Prepared statements (reused for performance)
export const stmts = {
  insertUser:    db.prepare('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)'),
  findUser:      db.prepare('SELECT id, username, password_hash, public_key FROM users WHERE username = ?'),
  updatePubKey:  db.prepare('UPDATE users SET public_key = ? WHERE id = ?'),
  listUsers:     db.prepare('SELECT username FROM users WHERE id != ? ORDER BY username'),
  userPubKey:    db.prepare('SELECT public_key FROM users WHERE username = ?'),

  insertMsg:     db.prepare(
    'INSERT INTO messages (sender_id, recipient_id, ciphertext, iv) VALUES (?, ?, ?, ?)'
  ),
  conversation:  db.prepare(`
    SELECT m.id, u.username AS sender, m.ciphertext, m.iv,
           m.created_at AS createdAt
    FROM   messages m
    JOIN   users u ON u.id = m.sender_id
    WHERE  (m.sender_id = ? AND m.recipient_id = ?)
        OR (m.sender_id = ? AND m.recipient_id = ?)
    ORDER  BY m.created_at ASC, m.id ASC
    LIMIT  200
  `),
}

export default db
