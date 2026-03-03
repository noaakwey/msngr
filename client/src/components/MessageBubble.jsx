import { useState } from 'react';

function formatTime(ts) {
  if (!ts) return '';
  return new Date(ts * 1000).toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' });
}

export default function MessageBubble({ msg, isOwn, isGroup, onReply, onEdit, onDelete }) {
  const [editing, setEditing] = useState(false);
  const [editText, setEditText] = useState(msg.content || '');

  if (msg.deleted) {
    return (
      <div className={`msg-wrap ${isOwn ? 'out' : 'in'}`}>
        <div className="bubble" style={{ opacity: 0.6 }}>
          <span className="bubble-deleted">Сообщение удалено</span>
        </div>
      </div>
    );
  }

  const handleEdit = () => {
    if (editText.trim() && editText !== msg.content) {
      onEdit(msg.id, editText.trim());
    }
    setEditing(false);
  };

  return (
    <div className={`msg-wrap ${isOwn ? 'out' : 'in'}`} style={{ position: 'relative' }}>
      {/* Actions on hover */}
      <div className="bubble-wrap" style={{ position: 'relative', maxWidth: '65%' }}>
        <div className="bubble-actions">
          <button className="bubble-action-btn" onClick={() => onReply(msg)} title="Ответить">↩</button>
          {isOwn && msg.type === 'text' && (
            <button className="bubble-action-btn" onClick={() => { setEditing(true); setEditText(msg.content); }} title="Редактировать">✏️</button>
          )}
          {isOwn && (
            <button className="bubble-action-btn" onClick={() => onDelete(msg.id)} title="Удалить" style={{ color: 'var(--danger)' }}>🗑</button>
          )}
        </div>

        <div className="bubble">
          {/* Sender name in groups */}
          {isGroup && !isOwn && msg.sender && (
            <div className="bubble-sender">
              {msg.sender.first_name}{msg.sender.last_name ? ' ' + msg.sender.last_name : ''}
            </div>
          )}

          {/* Reply preview */}
          {msg.replyTo && (
            <div className="reply-preview">
              <div className="reply-preview-sender">
                {msg.replyTo.sender_id === msg.sender_id ? 'Вы' : 'Собеседник'}
              </div>
              <div className="reply-preview-text">
                {msg.replyTo.type === 'text' ? msg.replyTo.content : '📎 Вложение'}
              </div>
            </div>
          )}

          {/* Content */}
          {editing ? (
            <div>
              <textarea
                value={editText}
                onChange={e => setEditText(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleEdit(); } if (e.key === 'Escape') setEditing(false); }}
                style={{ width: '100%', border: 'none', background: 'transparent', resize: 'none', outline: 'none', font: 'inherit', fontSize: 14 }}
                autoFocus
                rows={2}
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                <button onClick={handleEdit} style={{ fontSize: 12, cursor: 'pointer', background: 'var(--primary)', color: 'white', border: 'none', borderRadius: 6, padding: '2px 8px' }}>✓</button>
                <button onClick={() => setEditing(false)} style={{ fontSize: 12, cursor: 'pointer', background: 'var(--hover)', border: 'none', borderRadius: 6, padding: '2px 8px' }}>✕</button>
              </div>
            </div>
          ) : msg.type === 'image' ? (
            <img
              src={msg.file_url}
              alt={msg.file_name || 'image'}
              className="bubble-img"
              onClick={() => window.open(msg.file_url, '_blank')}
            />
          ) : msg.type === 'file' ? (
            <a className="bubble-file" href={msg.file_url} download={msg.file_name} target="_blank" rel="noopener noreferrer">
              <span className="bubble-file-icon">📎</span>
              <span className="bubble-file-name">{msg.file_name || 'Файл'}</span>
            </a>
          ) : (
            <div className="bubble-text">{msg.content}</div>
          )}

          <div className="bubble-meta">
            {msg.edited_at && <span className="bubble-edited">изменено</span>}
            <span>{formatTime(msg.created_at)}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
