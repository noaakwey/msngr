# Msngr

Полнофункциональный мессенджер с авторизацией через Telegram. Может быть развёрнут на любом сервере — как альтернатива Telegram для регионов с ограниченным доступом.

## Возможности

- **Авторизация через Telegram** — привычный вход, не нужно создавать отдельный аккаунт
- **Личные чаты** — переписка один на один
- **Групповые чаты** — создание групп с несколькими участниками
- **Передача файлов** — изображения и документы (до 20 МБ)
- **Статус "в сети"** — видно, кто сейчас онлайн
- **Индикатор набора** — показывает, когда собеседник печатает
- **Ответы на сообщения** — цитирование конкретного сообщения
- **Редактирование и удаление** — изменить или удалить своё сообщение
- **Счётчик непрочитанных** — сколько новых сообщений в каждом чате
- **Подгрузка истории** — листать старые сообщения
- **Свой сервер** — все данные на вашем сервере, а не в Telegram

## Стек

| Слой | Технологии |
|------|-----------|
| Backend | Node.js, Express, Socket.io |
| Database | SQLite (better-sqlite3) |
| Auth | Telegram Login Widget + JWT |
| Frontend | React 18, Vite |
| Real-time | WebSocket (Socket.io) |

## Быстрый старт

### 1. Создайте Telegram-бота

1. Откройте [@BotFather](https://t.me/BotFather) в Telegram
2. Выполните `/newbot`, задайте имя и username
3. Сохраните токен бота
4. Выполните `/setdomain` → выберите бота → укажите домен вашего сервера
   *(для разработки: используйте `localhost` или ngrok)*

### 2. Настройте окружение

```bash
# Корень проекта
cp .env.example server/.env
# Отредактируйте server/.env:
#   TELEGRAM_BOT_TOKEN=...
#   TELEGRAM_BOT_USERNAME=...
#   JWT_SECRET=$(openssl rand -hex 32)

# Клиент
cp client/.env.example client/.env
# Отредактируйте client/.env:
#   VITE_TELEGRAM_BOT_USERNAME=...
```

### 3. Установите зависимости и запустите

```bash
# Установить всё
npm run install:all

# Запустить в режиме разработки (оба сервера)
npm run dev

# Или по отдельности:
npm run dev:server   # http://localhost:3001
npm run dev:client   # http://localhost:5173
```

Откройте [http://localhost:5173](http://localhost:5173).

## Развёртывание в продакшн

```bash
# Сборка клиента
npm run build

# Запуск (сервер раздаёт собранный клиент)
NODE_ENV=production npm start
```

Сервер слушает `PORT` (по умолчанию 3001) и раздаёт клиент из `client/dist/`.

### Рекомендуемая инфраструктура

```
Интернет → Nginx (SSL, порт 443) → Node.js (порт 3001)
```

Пример Nginx-конфига:

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

## Структура проекта

```
msngr/
├── server/
│   ├── index.js          # Точка входа, Express + Socket.io
│   ├── db.js             # SQLite, инициализация схемы
│   ├── middleware/
│   │   └── auth.js       # JWT middleware
│   ├── routes/
│   │   ├── auth.js       # Telegram Login верификация
│   │   ├── users.js      # Поиск пользователей
│   │   ├── chats.js      # Чаты (приватные/группы)
│   │   └── messages.js   # Сообщения + загрузка файлов
│   └── uploads/          # Загруженные файлы
└── client/
    └── src/
        ├── App.jsx
        ├── api.js         # REST-клиент
        ├── socket.js      # Socket.io клиент
        └── components/
            ├── Login.jsx
            ├── Sidebar.jsx
            ├── ChatWindow.jsx
            ├── MessageBubble.jsx
            ├── MessageInput.jsx
            └── NewChatModal.jsx
```

## Безопасность

- Telegram Login данные верифицируются через HMAC-SHA256 с токеном бота
- Все эндпоинты защищены JWT
- Загружаемые файлы фильтруются по типу
- Foreign keys и WAL mode в SQLite
