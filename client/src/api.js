const BASE = '/api';

function getToken() {
  return localStorage.getItem('token');
}

async function request(method, path, body, isFormData = false) {
  const headers = {};
  const token = getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (!isFormData) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: isFormData ? body : body ? JSON.stringify(body) : undefined
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Request failed');
  }
  return res.json();
}

export const api = {
  // Auth
  loginTelegram: (data) => request('POST', '/auth/telegram', data),
  getMe: () => request('GET', '/auth/me'),

  // Users
  searchUsers: (q) => request('GET', `/users/search?q=${encodeURIComponent(q)}`),
  getUser: (id) => request('GET', `/users/${id}`),

  // Chats
  getChats: () => request('GET', '/chats'),
  getChat: (id) => request('GET', `/chats/${id}`),
  createPrivateChat: (userId) => request('POST', '/chats/private', { userId }),
  createGroupChat: (name, memberIds) => request('POST', '/chats/group', { name, memberIds }),
  addMember: (chatId, userId) => request('POST', `/chats/${chatId}/members`, { userId }),
  markRead: (chatId, messageId) => request('POST', `/chats/${chatId}/read`, { messageId }),

  // Messages
  getMessages: (chatId, before) =>
    request('GET', `/messages/${chatId}${before ? `?before=${before}` : ''}`),
  sendMessage: (chatId, content, replyTo) =>
    request('POST', `/messages/${chatId}`, { content, reply_to: replyTo }),
  sendFile: (chatId, formData) =>
    request('POST', `/messages/${chatId}`, formData, true),
  editMessage: (chatId, msgId, content) =>
    request('PATCH', `/messages/${chatId}/${msgId}`, { content }),
  deleteMessage: (chatId, msgId) =>
    request('DELETE', `/messages/${chatId}/${msgId}`)
};
