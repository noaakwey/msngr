const express = require('express');
const db = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);

function chatWithMeta(chatId, userId) {
  const chat = db.prepare('SELECT * FROM chats WHERE id = ?').get(chatId);
  if (!chat) return null;

  const members = db.prepare(`
    SELECT u.id, u.first_name, u.last_name, u.username, u.photo_url, cm.role
    FROM chat_members cm JOIN users u ON u.id = cm.user_id
    WHERE cm.chat_id = ?
  `).all(chatId);

  const lastMessage = db.prepare(`
    SELECT m.*, u.first_name as sender_first_name
    FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.chat_id = ? AND m.deleted = 0
    ORDER BY m.created_at DESC LIMIT 1
  `).get(chatId);

  const unread = db.prepare(`
    SELECT COUNT(*) as count FROM messages m
    JOIN chat_members cm ON cm.chat_id = m.chat_id AND cm.user_id = ?
    WHERE m.chat_id = ? AND m.sender_id != ? AND m.deleted = 0
      AND m.id > COALESCE(cm.last_read_message_id, 0)
  `).get(userId, chatId, userId);

  // For private chats, use the other person's name
  let displayName = chat.name;
  let displayPhoto = null;
  if (chat.type === 'private') {
    const other = members.find(m => m.id !== userId);
    if (other) {
      displayName = [other.first_name, other.last_name].filter(Boolean).join(' ');
      displayPhoto = other.photo_url;
    }
  }

  return { ...chat, displayName, displayPhoto, members, lastMessage, unreadCount: unread.count };
}

// GET /api/chats
router.get('/', (req, res) => {
  const chatIds = db.prepare(`
    SELECT cm.chat_id FROM chat_members cm
    WHERE cm.user_id = ?
    ORDER BY (
      SELECT created_at FROM messages WHERE chat_id = cm.chat_id AND deleted = 0 ORDER BY created_at DESC LIMIT 1
    ) DESC NULLS LAST
  `).all(req.user.id).map(r => r.chat_id);

  const chats = chatIds.map(id => chatWithMeta(id, req.user.id)).filter(Boolean);
  res.json(chats);
});

// POST /api/chats/private
router.post('/private', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (userId === req.user.id) return res.status(400).json({ error: 'Cannot chat with yourself' });

  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  // Check if private chat already exists
  const existing = db.prepare(`
    SELECT cm1.chat_id FROM chat_members cm1
    JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
    JOIN chats c ON c.id = cm1.chat_id
    WHERE cm1.user_id = ? AND cm2.user_id = ? AND c.type = 'private'
  `).get(req.user.id, userId);

  if (existing) {
    return res.json(chatWithMeta(existing.chat_id, req.user.id));
  }

  const chat = db.transaction(() => {
    const result = db.prepare(
      "INSERT INTO chats (type, created_by) VALUES ('private', ?)"
    ).run(req.user.id);
    const chatId = result.lastInsertRowid;
    db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, req.user.id);
    db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, userId);
    return chatId;
  })();

  res.status(201).json(chatWithMeta(chat, req.user.id));
});

// POST /api/chats/group
router.post('/group', (req, res) => {
  const { name, memberIds = [] } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name required' });

  const chatId = db.transaction(() => {
    const result = db.prepare(
      "INSERT INTO chats (name, type, created_by) VALUES (?, 'group', ?)"
    ).run(name, req.user.id);
    const id = result.lastInsertRowid;
    const allMembers = [...new Set([req.user.id, ...memberIds])];
    for (const uid of allMembers) {
      const role = uid === req.user.id ? 'admin' : 'member';
      db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, ?)').run(id, uid, role);
    }
    return id;
  })();

  res.status(201).json(chatWithMeta(chatId, req.user.id));
});

// POST /api/chats/:id/members
router.post('/:id/members', (req, res) => {
  const chatId = parseInt(req.params.id);
  const { userId } = req.body;

  const member = db.prepare('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, req.user.id);
  if (!member || member.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

  db.prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)').run(chatId, userId);
  res.json({ ok: true });
});

// GET /api/chats/:id
router.get('/:id', (req, res) => {
  const chatId = parseInt(req.params.id);
  const member = db.prepare('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });
  res.json(chatWithMeta(chatId, req.user.id));
});

// Mark messages as read
router.post('/:id/read', (req, res) => {
  const chatId = parseInt(req.params.id);
  const { messageId } = req.body;
  db.prepare(`
    UPDATE chat_members SET last_read_message_id = MAX(COALESCE(last_read_message_id, 0), ?)
    WHERE chat_id = ? AND user_id = ?
  `).run(messageId, chatId, req.user.id);
  res.json({ ok: true });
});

module.exports = router;
