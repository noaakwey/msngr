const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

function verifyTelegramAuth(data) {
  const { hash, ...fields } = data;
  if (!hash) return false;

  const checkString = Object.keys(fields)
    .sort()
    .map(k => `${k}=${fields[k]}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256')
    .update(process.env.TELEGRAM_BOT_TOKEN)
    .digest();

  const expectedHash = crypto.createHmac('sha256', secretKey)
    .update(checkString)
    .digest('hex');

  if (expectedHash !== hash) return false;

  // Auth data must not be older than 1 day
  const age = Math.floor(Date.now() / 1000) - parseInt(fields.auth_date || 0);
  if (age > 86400) return false;

  return true;
}

// POST /api/auth/telegram
router.post('/telegram', (req, res) => {
  const data = req.body;

  if (!verifyTelegramAuth(data)) {
    return res.status(401).json({ error: 'Invalid Telegram auth data' });
  }

  const telegramId = parseInt(data.id);
  const user = db.prepare(`
    INSERT INTO users (id, telegram_id, username, first_name, last_name, photo_url)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(telegram_id) DO UPDATE SET
      username = excluded.username,
      first_name = excluded.first_name,
      last_name = excluded.last_name,
      photo_url = excluded.photo_url
    RETURNING *
  `).get(telegramId, telegramId, data.username || null, data.first_name, data.last_name || null, data.photo_url || null);

  const token = jwt.sign(
    { id: user.id, telegram_id: user.telegram_id, first_name: user.first_name },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ token, user });
});

// GET /api/auth/me
router.get('/me', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

module.exports = router;
