#!/usr/bin/env bash
# SENTINEL / Linux IR Console — 一键启动
set -u
cd "$(dirname "$0")"

echo
echo "  ============================================================"
echo "    SENTINEL // LINUX INCIDENT RESPONSE CONSOLE"
echo "  ============================================================"
echo

if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else
  echo "  [X] 未找到 Python 3，请先安装 Python 3.9+"; exit 1
fi

echo "  [*] 检查 / 安装 SSH 依赖 paramiko ..."
"$PY" -m pip install -r requirements.txt --disable-pip-version-check -q \
  || echo "  [!] 依赖自动安装失败，服务启动后会在页面内重试（演示模式不受影响）"

echo "  [*] 启动本地控制台: http://127.0.0.1:8765"
echo "  [*] 按 Ctrl+C 停止服务"
echo
exec "$PY" server.py --port 8765
