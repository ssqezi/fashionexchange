#!/bin/bash
# Fashion Exchange Public Sharing Helper (via Cloudflare Tunnel)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_BIN="/Users/arseniybogdevich/.local/bin/node"
CLOUDFLARED_BIN="/Users/arseniybogdevich/.local/bin/cloudflared"
PROXY_SCRIPT="/Users/arseniybogdevich/.local/bin/fx-tunnel-proxy.mjs"

# 1. Check if Fashion Exchange is running on port 3007
if ! lsof -i :3007 > /dev/null 2>&1; then
    echo "⚠️  Локальный сервер Fashion Exchange не запущен на порту 3007."
    echo "Запустите сначала сервер командой: npm start"
    exit 1
fi

echo "✅ Локальный сервер Fashion Exchange обнаружен на порту 3007."

# 2. Check/Start proxy on port 3008 if not already running
if ! lsof -i :3008 > /dev/null 2>&1; then
    echo "🚀 Запуск прокси-адаптера заголовков на порту 3008..."
    $NODE_BIN "$PROXY_SCRIPT" > /tmp/fx-proxy.log 2>&1 &
    sleep 1
fi

echo "✅ Прокси активен на порту 3008."
echo "🌐 Запуск публичного HTTPS туннеля Cloudflare..."
echo "--------------------------------------------------------"

$CLOUDFLARED_BIN tunnel --url http://127.0.0.1:3008
