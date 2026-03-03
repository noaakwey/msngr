import { useState, useEffect, useCallback } from 'react';
import { api } from './api.js';
import { connectSocket, disconnectSocket, getSocket } from './socket.js';
import Login from './components/Login.jsx';
import Sidebar from './components/Sidebar.jsx';
import ChatWindow from './components/ChatWindow.jsx';

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedChat, setSelectedChat] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState(new Set());
  const [chats, setChats] = useState([]);

  // Restore session
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) { setLoading(false); return; }
    api.getMe()
      .then(u => { setUser(u); setupSocket(token); })
      .catch(() => localStorage.removeItem('token'))
      .finally(() => setLoading(false));
  }, []);

  function setupSocket(token) {
    const socket = connectSocket(token);

    socket.on('users:online', (ids) => setOnlineUsers(new Set(ids)));
    socket.on('user:online', ({ userId }) => setOnlineUsers(prev => new Set([...prev, userId])));
    socket.on('user:offline', ({ userId }) => setOnlineUsers(prev => { const s = new Set(prev); s.delete(userId); return s; }));

    socket.on('message:new', (msg) => {
      setChats(prev => prev.map(c => {
        if (c.id !== msg.chat_id) return c;
        const isSelected = selectedChat?.id === msg.chat_id;
        const newUnread = isSelected ? 0 : (c.unreadCount || 0) + 1;
        return { ...c, lastMessage: msg, unreadCount: newUnread };
      }));
    });

    return socket;
  }

  const handleLogin = useCallback((token, userData) => {
    localStorage.setItem('token', token);
    setUser(userData);
    setupSocket(token);
  }, []);

  const handleLogout = useCallback(() => {
    localStorage.removeItem('token');
    disconnectSocket();
    setUser(null);
    setSelectedChat(null);
    setChats([]);
    setOnlineUsers(new Set());
  }, []);

  const handleSelectChat = useCallback((chat) => {
    setSelectedChat(chat);
    // Join socket room
    const socket = getSocket();
    if (socket) socket.emit('chat:join', chat.id);
    // Mark as read
    if (chat.lastMessage) {
      api.markRead(chat.id, chat.lastMessage.id).catch(() => {});
      setChats(prev => prev.map(c => c.id === chat.id ? { ...c, unreadCount: 0 } : c));
    }
  }, []);

  const handleNewChat = useCallback((chat) => {
    setChats(prev => {
      const exists = prev.find(c => c.id === chat.id);
      if (exists) return prev;
      return [chat, ...prev];
    });
    handleSelectChat(chat);
  }, [handleSelectChat]);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg)' }}>
        <div style={{ fontSize: 32 }}>💬</div>
      </div>
    );
  }

  if (!user) return <Login onLogin={handleLogin} />;

  return (
    <div className="app">
      <Sidebar
        user={user}
        chats={chats}
        setChats={setChats}
        selectedChat={selectedChat}
        onlineUsers={onlineUsers}
        onSelectChat={handleSelectChat}
        onNewChat={handleNewChat}
        onLogout={handleLogout}
      />
      {selectedChat ? (
        <ChatWindow
          key={selectedChat.id}
          chat={selectedChat}
          user={user}
          onlineUsers={onlineUsers}
          onUpdateChat={(updated) => setChats(prev => prev.map(c => c.id === updated.id ? updated : c))}
        />
      ) : (
        <div className="no-chat">
          <div className="no-chat-icon">💬</div>
          <div>Выберите чат, чтобы начать общение</div>
        </div>
      )}
    </div>
  );
}
