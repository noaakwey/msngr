import { useState, useCallback } from 'react';
import { api } from '../api.js';

function UserResult({ u, selected, onClick }) {
  const name = [u.first_name, u.last_name].filter(Boolean).join(' ');
  return (
    <div className={`user-result${selected ? ' selected' : ''}`} onClick={onClick}>
      <div className="user-result-avatar">
        {u.photo_url
          ? <img src={u.photo_url} alt="" />
          : name[0]?.toUpperCase()}
      </div>
      <div>
        <div className="user-result-name">{name}</div>
        {u.username && <div className="user-result-username">@{u.username}</div>}
      </div>
    </div>
  );
}

export default function NewChatModal({ onClose, onCreated }) {
  const [tab, setTab] = useState('private'); // 'private' | 'group'
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [selected, setSelected] = useState([]);
  const [groupName, setGroupName] = useState('');
  const [loading, setLoading] = useState(false);

  const search = useCallback(async (q) => {
    setQuery(q);
    if (!q.trim()) { setResults([]); return; }
    try {
      const users = await api.searchUsers(q);
      setResults(users);
    } catch {}
  }, []);

  const toggleSelect = (u) => {
    setSelected(prev =>
      prev.find(x => x.id === u.id) ? prev.filter(x => x.id !== u.id) : [...prev, u]
    );
  };

  const handleCreate = async () => {
    setLoading(true);
    try {
      if (tab === 'private') {
        if (!selected[0]) return;
        const chat = await api.createPrivateChat(selected[0].id);
        onCreated(chat);
      } else {
        if (!groupName.trim() || selected.length === 0) return;
        const chat = await api.createGroupChat(groupName.trim(), selected.map(u => u.id));
        onCreated(chat);
      }
    } catch (err) {
      alert('Ошибка: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const canCreate = tab === 'private' ? selected.length === 1 : (groupName.trim() && selected.length > 0);

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <h2>Новый чат</h2>

        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          {['private', 'group'].map(t => (
            <button
              key={t}
              onClick={() => { setTab(t); setSelected([]); }}
              style={{
                flex: 1, padding: '8px 0', border: 'none', borderRadius: 10, cursor: 'pointer',
                background: tab === t ? 'var(--primary)' : 'var(--hover)',
                color: tab === t ? 'white' : 'var(--text)', fontWeight: 600, fontSize: 14
              }}
            >
              {t === 'private' ? '💬 Личное' : '👥 Группа'}
            </button>
          ))}
        </div>

        {tab === 'group' && (
          <input
            className="modal-input"
            placeholder="Название группы"
            value={groupName}
            onChange={e => setGroupName(e.target.value)}
          />
        )}

        <input
          className="modal-input"
          placeholder="Поиск пользователей..."
          value={query}
          onChange={e => search(e.target.value)}
          autoFocus
        />

        {selected.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
            {selected.map(u => (
              <span
                key={u.id}
                onClick={() => toggleSelect(u)}
                style={{
                  background: 'var(--primary)', color: 'white', padding: '3px 10px',
                  borderRadius: 12, fontSize: 13, cursor: 'pointer'
                }}
              >
                {u.first_name} ✕
              </span>
            ))}
          </div>
        )}

        <div className="search-results">
          {results.map(u => (
            <UserResult
              key={u.id}
              u={u}
              selected={!!selected.find(x => x.id === u.id)}
              onClick={() => tab === 'private' ? setSelected([u]) : toggleSelect(u)}
            />
          ))}
          {query && results.length === 0 && (
            <div style={{ color: 'var(--text-secondary)', fontSize: 14, textAlign: 'center', padding: 12 }}>
              Пользователи не найдены
            </div>
          )}
        </div>

        <div className="modal-actions">
          <button className="btn-secondary" onClick={onClose}>Отмена</button>
          <button className="btn-primary" onClick={handleCreate} disabled={!canCreate || loading}>
            {loading ? '...' : 'Создать'}
          </button>
        </div>
      </div>
    </div>
  );
}
