import { useEffect, useRef } from 'react';
import { api } from '../api.js';

const BOT_USERNAME = import.meta.env.VITE_TELEGRAM_BOT_USERNAME || 'your_bot_username';

export default function Login({ onLogin }) {
  const widgetRef = useRef(null);

  useEffect(() => {
    // Telegram Login Widget calls this global function
    window.onTelegramAuth = async (telegramUser) => {
      try {
        const { token, user } = await api.loginTelegram(telegramUser);
        onLogin(token, user);
      } catch (err) {
        alert('Ошибка авторизации: ' + err.message);
      }
    };

    // Dynamically inject the Telegram widget script with callback
    const script = document.createElement('script');
    script.src = 'https://telegram.org/js/telegram-widget.js?22';
    script.async = true;
    script.setAttribute('data-telegram-login', BOT_USERNAME);
    script.setAttribute('data-size', 'large');
    script.setAttribute('data-onauth', 'onTelegramAuth(user)');
    script.setAttribute('data-request-access', 'write');
    script.setAttribute('data-lang', 'ru');

    if (widgetRef.current) {
      widgetRef.current.innerHTML = '';
      widgetRef.current.appendChild(script);
    }

    return () => {
      delete window.onTelegramAuth;
    };
  }, [onLogin]);

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">💬</div>
        <h1>Msngr</h1>
        <p>
          Надёжный мессенджер без ограничений.<br />
          Войдите через Telegram — вы уже там зарегистрированы.
        </p>
        <div className="login-tg-wrap" ref={widgetRef} />
        <p className="login-note">
          Авторизация происходит через серверы Telegram.<br />
          Ваши сообщения хранятся на вашем сервере.
        </p>
      </div>
    </div>
  );
}
