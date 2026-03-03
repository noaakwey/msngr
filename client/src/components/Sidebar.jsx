import { useEffect, useState, useCallback } from 'react';
import { api } from '../api.js';
import NewChatModal from './NewChatModal.jsx';

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString('ru', { day: '2-digit', month: '2-digit' });
}

function Avatar({ name, photo, size = 48, online }) {
  const letter = (name || '?')[0].toUpperCase();
  return (
    <div className="chat-avatar" style={{ width: size, height: size, fontSize: size * 0.4 }}>
      {photo
        ? <img src={photo} alt={name} onError={e => { e.target.style.display = 'none'; }} />
        : letter}
      {online && <div className="online-dot" />}
    </div>
  );
}

export default function Sidebar({ user, chats, setChats, selectedChat, onlineUsers, onSelectChat, onNewChat, onLogout }) {
  const [search, setSearch] = useState('');
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getChats()
      .then(setChats)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [setChats]);

  const filtered = chats.filter(c => {
    const name = (c.displayName || c.name || '').toLowerCase();
    return name.includes(search.toLowerCase());
  });

  const isOnline = useCallback((chat) => {
    if (chat.type !== 'private') return false;
    const other = chat.members?.find(m => m.id !== user.id);
    return other ? onlineUsers.has(other.id) : false;
  }, [user.id, onlineUsers]);

  const displayName = user ? `${user.first_name}${user.last_name ? ' ' + user.last_name : ''}` : '';

  return (
    <>
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-header-avatar" title={displayName}>
            {user?.photo_url
              ? <img src={user.photo_url} alt="" style={{ width: 40, height: 40, borderRadius: '50%', objectFit: 'cover' }} />
              : displayName[0]?.toUpperCase()}
          </div>
          <div className="sidebar-header-name">{displayName}</div>
          <button className="icon-btn" onClick={() => setShowModal(true)} title="Новый чат">✏️</button>
          <button className="icon-btn" onClick={onLogout} title="Выйти">🚪</button>
        </div>

        <div className="sidebar-search">
          <span className="sidebar-search-icon">🔍</span>
          <input
            placeholder="Поиск чатов..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="chat-list">
          {loading && <div style={{ padding: 16, color: 'var(--text-secondary)', fontSize: 14 }}>Загрузка...</div>}
          {!loading && filtered.length === 0 && (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-secondary)', fontSize: 14 }}>
              {search ? 'Ничего не найдено' : 'Нет чатов. Нажмите ✏️ чтобы начать.'}
            </div>
          )}
          {filtered.map(chat => {
            const lm = chat.lastMessage;
            const preview = lm
              ? lm.type === 'text' ? lm.content
              : lm.type === 'image' ? '🖼 Фото'
              : '📎 Файл'
              : 'Нет сообщений';

            return (
              <div
                key={chat.id}
                className={`chat-item${selectedChat?.id === chat.id ? ' active' : ''}`}
                onClick={() => onSelectChat(chat)}
              >
                <Avatar
                  name={chat.displayName || chat.name}
                  photo={chat.displayPhoto}
                  online={isOnline(chat)}
                />
                <div className="chat-info">
                  <div className="chat-info-top">
                    <div className="chat-name">{chat.displayName || chat.name}</div>
                    <div className="chat-time">{formatTime(lm?.created_at)}</div>
                  </div>
                  <div className="chat-info-bottom">
                    <div className="chat-last-msg">{preview}</div>
                    {chat.unreadCount > 0 && (
                      <div className="unread-badge">{chat.unreadCount > 99 ? '99+' : chat.unreadCount}</div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {showModal && (
        <NewChatModal
          currentUser={user}
          onClose={() => setShowModal(false)}
          onCreated={(chat) => { onNewChat(chat); setShowModal(false); }}
        />
      )}
    </>
  );
}
