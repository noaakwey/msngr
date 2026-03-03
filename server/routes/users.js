const express = require('express');
const db = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();
router.use(auth);

// GET /api/users/search?q=...
router.get('/search', (req, res) => {
  const q = `%${req.query.q || ''}%`;
  const users = db.prepare(`
    SELECT id, telegram_id, username, first_name, last_name, photo_url
    FROM users
    WHERE id != ?
      AND (first_name LIKE ? OR last_name LIKE ? OR username LIKE ?)
    LIMIT 20
  `).all(req.user.id, q, q, q);
  res.json(users);
});

// GET /api/users/:id
router.get('/:id', (req, res) => {
  const user = db.prepare(`
    SELECT id, telegram_id, username, first_name, last_name, photo_url, created_at
    FROM users WHERE id = ?
  `).get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

module.exports = router;
