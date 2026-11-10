#!/bin/bash
# Установка sb-ipv6-leak: curl -fsSL https://raw.githubusercontent.com/Anton98567/sb-ipv6-leak/main/install.sh | bash
set -euo pipefail
URL="https://raw.githubusercontent.com/Anton98567/sb-ipv6-leak/main/sb-ipv6-leak.sh"
DEST="${1:-/usr/local/sbin/sb-ipv6-leak}"
curl -fsSL "$URL" -o "$DEST"
chmod 755 "$DEST"
echo "установлено: $DEST"
"$DEST" version
