import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../api.js';
import { getSocket } from '../socket.js';
import MessageBubble from './MessageBubble.jsx';
import MessageInput from './MessageInput.jsx';

function formatDate(ts) {
  const d = new Date(ts * 1000);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Сегодня';
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return 'Вчера';
  return d.toLocaleDateString('ru', { day: 'numeric', month: 'long', year: 'numeric' });
}

function groupByDate(messages) {
  const groups = [];
  let currentDate = null;
  for (const msg of messages) {
    const dateLabel = formatDate(msg.created_at);
    if (dateLabel !== currentDate) {
      currentDate = dateLabel;
      groups.push({ type: 'date', label: dateLabel, key: `date-${msg.id}` });
    }
    groups.push({ type: 'message', msg, key: msg.id });
  }
  return groups;
}

export default function ChatWindow({ chat, user, onlineUsers, onUpdateChat }) {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(false);
  const [replyTo, setReplyTo] = useState(null);
  const [typingUsers, setTypingUsers] = useState(new Set());
  const bottomRef = useRef(null);
  const scrollRef = useRef(null);

  const isGroup = chat.type === 'group';
  const other = !isGroup ? chat.members?.find(m => m.id !== user.id) : null;
  const isOtherOnline = other ? onlineUsers.has(other.id) : false;

  const displayName = isGroup ? chat.name : (other ? [other.first_name, other.last_name].filter(Boolean).join(' ') : '?');
  const statusText = isGroup
    ? `${chat.members?.length || 0} участников`
    : isOtherOnline ? 'в сети' : 'не в сети';

  // Load messages
  useEffect(() => {
    setLoading(true);
    setMessages([]);
    api.getMessages(chat.id)
      .then(msgs => {
        setMessages(msgs);
        setHasMore(msgs.length >= 50);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [chat.id]);

  // Scroll to bottom on initial load
  useEffect(() => {
    if (!loading) bottomRef.current?.scrollIntoView({ behavior: 'instant' });
  }, [loading]);

  // Socket events
  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const onNew = (msg) => {
      if (msg.chat_id !== chat.id) return;
      setMessages(prev => [...prev, msg]);
      setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
      api.markRead(chat.id, msg.id).catch(() => {});
    };

    const onEdited = (msg) => {
      if (msg.chat_id !== chat.id) return;
      setMessages(prev => prev.map(m => m.id === msg.id ? msg : m));
    };

    const onDeleted = ({ id, chatId }) => {
      if (chatId !== chat.id) return;
      setMessages(prev => prev.map(m => m.id === id ? { ...m, deleted: 1 } : m));
    };

    const onTypingStart = ({ chatId, userId }) => {
      if (chatId !== chat.id || userId === user.id) return;
      setTypingUsers(prev => new Set([...prev, userId]));
    };

    const onTypingStop = ({ chatId, userId }) => {
      if (chatId !== chat.id) return;
      setTypingUsers(prev => { const s = new Set(prev); s.delete(userId); return s; });
    };

    socket.on('message:new', onNew);
    socket.on('message:edited', onEdited);
    socket.on('message:deleted', onDeleted);
    socket.on('typing:start', onTypingStart);
    socket.on('typing:stop', onTypingStop);

    return () => {
      socket.off('message:new', onNew);
      socket.off('message:edited', onEdited);
      socket.off('message:deleted', onDeleted);
      socket.off('typing:start', onTypingStart);
      socket.off('typing:stop', onTypingStop);
    };
  }, [chat.id, user.id]);

  const loadMore = async () => {
    if (!messages.length) return;
    const oldest = messages[0].id;
    const prev = await api.getMessages(chat.id, oldest);
    setMessages(old => [...prev, ...old]);
    setHasMore(prev.length >= 50);
  };

  const handleSend = useCallback(async (content, replyToId) => {
    try {
      await api.sendMessage(chat.id, content, replyToId);
    } catch (err) {
      alert('Ошибка отправки: ' + err.message);
    }
  }, [chat.id]);

  const handleSendFile = useCallback(async (formData) => {
    try {
      await api.sendFile(chat.id, formData);
    } catch (err) {
      alert('Ошибка загрузки файла: ' + err.message);
    }
  }, [chat.id]);

  const handleEdit = useCallback(async (msgId, content) => {
    try {
      await api.editMessage(chat.id, msgId, content);
    } catch (err) {
      alert('Ошибка редактирования: ' + err.message);
    }
  }, [chat.id]);

  const handleDelete = useCallback(async (msgId) => {
    if (!window.confirm('Удалить сообщение?')) return;
    try {
      await api.deleteMessage(chat.id, msgId);
    } catch (err) {
      alert('Ошибка удаления: ' + err.message);
    }
  }, [chat.id]);

  const typingNames = [...typingUsers].map(uid => {
    const m = chat.members?.find(x => x.id === uid);
    return m ? m.first_name : 'Кто-то';
  });

  const grouped = groupByDate(messages);

  return (
    <div className="chat-window">
      {/* Top bar */}
      <div className="chat-topbar">
        <div className="chat-avatar" style={{ width: 40, height: 40, fontSize: 16, flexShrink: 0 }}>
          {chat.displayPhoto
            ? <img src={chat.displayPhoto} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            : (displayName[0] || '?').toUpperCase()}
          {!isGroup && isOtherOnline && <div className="online-dot" />}
        </div>
        <div className="chat-topbar-info">
          <div className="chat-topbar-name">{displayName}</div>
          <div className="chat-topbar-status">{statusText}</div>
        </div>
      </div>

      {/* Messages */}
      <div className="messages-area" ref={scrollRef}>
        {loading && <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: 20 }}>Загрузка...</div>}

        {!loading && hasMore && (
          <button className="load-more-btn" onClick={loadMore}>Загрузить ранее</button>
        )}

        {grouped.map(item =>
          item.type === 'date' ? (
            <div className="messages-date-divider" key={item.key}>
              <span>{item.label}</span>
            </div>
          ) : (
            <MessageBubble
              key={item.key}
              msg={item.msg}
              isOwn={item.msg.sender_id === user.id}
              isGroup={isGroup}
              onReply={setReplyTo}
              onEdit={handleEdit}
              onDelete={handleDelete}
            />
          )
        )}

        {typingNames.length > 0 && (
          <div className="typing-indicator">
            {typingNames.join(', ')} {typingNames.length === 1 ? 'печатает' : 'печатают'}...
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <MessageInput
        chatId={chat.id}
        replyTo={replyTo}
        onCancelReply={() => setReplyTo(null)}
        onSend={handleSend}
        onSendFile={handleSendFile}
      />
    </div>
  );
}
