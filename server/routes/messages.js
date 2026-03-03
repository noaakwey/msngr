const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);

const storage = multer.diskStorage({
  destination: path.join(__dirname, '../uploads'),
  filename: (req, file, cb) => {
    const hash = crypto.randomBytes(8).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^a-z0-9.]/g, '');
    cb(null, `${hash}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|webp|pdf|txt|zip|mp4|mp3|ogg|wav)$/i;
    if (allowed.test(file.originalname)) cb(null, true);
    else cb(new Error('File type not allowed'));
  }
});

function formatMessage(msg) {
  if (!msg) return null;
  const sender = db.prepare('SELECT id, first_name, last_name, username, photo_url FROM users WHERE id = ?').get(msg.sender_id);
  const replyTo = msg.reply_to
    ? db.prepare('SELECT id, content, type, sender_id FROM messages WHERE id = ?').get(msg.reply_to)
    : null;
  return { ...msg, sender, replyTo };
}

// GET /api/messages/:chatId
router.get('/:chatId', (req, res) => {
  const chatId = parseInt(req.params.chatId);
  const before = req.query.before ? parseInt(req.query.before) : null;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);

  const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });

  let msgs;
  if (before) {
    msgs = db.prepare(`
      SELECT * FROM messages WHERE chat_id = ? AND deleted = 0 AND id < ?
      ORDER BY id DESC LIMIT ?
    `).all(chatId, before, limit);
  } else {
    msgs = db.prepare(`
      SELECT * FROM messages WHERE chat_id = ? AND deleted = 0
      ORDER BY id DESC LIMIT ?
    `).all(chatId, limit);
  }

  res.json(msgs.reverse().map(formatMessage));
});

// POST /api/messages/:chatId
router.post('/:chatId', upload.single('file'), (req, res) => {
  const chatId = parseInt(req.params.chatId);
  const member = db.prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?').get(chatId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Forbidden' });

  const { content, reply_to } = req.body;
  const file = req.file;

  if (!content && !file) return res.status(400).json({ error: 'content or file required' });

  let type = 'text';
  let fileUrl = null;
  let fileName = null;

  if (file) {
    const imageExts = /\.(jpg|jpeg|png|gif|webp)$/i;
    type = imageExts.test(file.originalname) ? 'image' : 'file';
    fileUrl = `/uploads/${file.filename}`;
    fileName = file.originalname;
  }

  const result = db.prepare(`
    INSERT INTO messages (chat_id, sender_id, type, content, file_url, file_name, reply_to)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(chatId, req.user.id, type, content || null, fileUrl, fileName, reply_to ? parseInt(reply_to) : null);

  const msg = formatMessage(db.prepare('SELECT * FROM messages WHERE id = ?').get(result.lastInsertRowid));

  // Emit via socket (attached to app)
  const io = req.app.get('io');
  if (io) io.to(`chat:${chatId}`).emit('message:new', msg);

  res.status(201).json(msg);
});

// PATCH /api/messages/:chatId/:id
router.patch('/:chatId/:id', (req, res) => {
  const msgId = parseInt(req.params.id);
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'content required' });

  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  if (!msg || msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  if (msg.type !== 'text') return res.status(400).json({ error: 'Can only edit text messages' });

  db.prepare('UPDATE messages SET content = ?, edited_at = unixepoch() WHERE id = ?').run(content, msgId);
  const updated = formatMessage(db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId));

  const io = req.app.get('io');
  if (io) io.to(`chat:${parseInt(req.params.chatId)}`).emit('message:edited', updated);

  res.json(updated);
});

// DELETE /api/messages/:chatId/:id
router.delete('/:chatId/:id', (req, res) => {
  const msgId = parseInt(req.params.id);
  const chatId = parseInt(req.params.chatId);

  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  if (!msg || msg.sender_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

  db.prepare('UPDATE messages SET deleted = 1 WHERE id = ?').run(msgId);

  const io = req.app.get('io');
  if (io) io.to(`chat:${chatId}`).emit('message:deleted', { id: msgId, chatId });

  res.json({ ok: true });
});

module.exports = router;
