import { useState, useRef, useEffect, useCallback } from 'react';
import { getSocket } from '../socket.js';

export default function MessageInput({ chatId, replyTo, onCancelReply, onSend, onSendFile }) {
  const [text, setText] = useState('');
  const textareaRef = useRef(null);
  const typingRef = useRef(false);
  const typingTimeoutRef = useRef(null);

  useEffect(() => {
    textareaRef.current?.focus();
  }, [chatId]);

  const sendTyping = useCallback((isTyping) => {
    const socket = getSocket();
    if (!socket) return;
    if (isTyping && !typingRef.current) {
      typingRef.current = true;
      socket.emit('typing:start', { chatId });
    }
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      typingRef.current = false;
      socket.emit('typing:stop', { chatId });
    }, 2000);
  }, [chatId]);

  const handleChange = (e) => {
    setText(e.target.value);
    sendTyping(true);
    // Auto-resize
    const ta = e.target;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleSubmit = () => {
    const trimmed = text.trim();
    if (!trimmed) return;
    onSend(trimmed, replyTo?.id);
    setText('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
    onCancelReply();
    // Stop typing
    const socket = getSocket();
    if (socket) socket.emit('typing:stop', { chatId });
    typingRef.current = false;
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    if (replyTo) fd.append('reply_to', replyTo.id);
    onSendFile(fd);
    e.target.value = '';
    onCancelReply();
  };

  return (
    <div>
      {replyTo && (
        <div className="reply-bar">
          <div className="reply-bar-text">
            ↩ {replyTo.type === 'text' ? replyTo.content : '📎 Вложение'}
          </div>
          <button className="reply-cancel" onClick={onCancelReply}>✕</button>
        </div>
      )}
      <div className="msg-input-area">
        <div className="msg-input-wrap">
          <textarea
            ref={textareaRef}
            className="msg-input"
            placeholder="Сообщение..."
            value={text}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            rows={1}
          />
          <label className="attach-btn" title="Прикрепить файл">
            📎
            <input type="file" hidden onChange={handleFileChange} accept="image/*,.pdf,.txt,.zip,.mp4,.mp3" />
          </label>
        </div>
        <button className="send-btn" onClick={handleSubmit} disabled={!text.trim()} title="Отправить">
          ➤
        </button>
      </div>
    </div>
  );
}
