#!/bin/bash
# sb-ipv6-leak v1.0.0 — проверка и устранение утечки IPv6 в клиентских конфигах sing-box.
#
# ПРОБЛЕМА: TUN-инбаунд с адресом ТОЛЬКО IPv4 (например, 10.0.0.1/28) захватывает
# маршрут лишь одного семейства. На dual-stack устройствах клиента IPv6-трафик
# уходит МИМО туннеля напрямую — реальный IPv6 виден сайтам (классическая
# «утечка IPv6»). Плюс два смежных вектора: auto_route=false (захвата вообще нет)
# и strict_route=false (ОС может строить обходные маршруты).
#
# ЧТО ДЕЛАЕТ ПАТЧ: в TUN-инбаунд добавляется IPv6-CIDR (ULA, по умолчанию
# fdfe:dcba:9876::1/64) и включаются auto_route/strict_route. Теперь туннель
# захватывает оба семейства, IPv6 идёт через прокси. Ссылки/пароли конфигов
# не меняются; клиенты подхватывают правку при обновлении подписки/импорте.
#
# КОМАНДЫ:
#   sb-ipv6-leak.sh check  [каталог]            — найти конфиги и показать векторы утечки
#   sb-ipv6-leak.sh status [каталог]            — сводка: что пропатчено, что нет
#   sb-ipv6-leak.sh patch  [каталог]            — применить патч (+ бэкап, идемпотентно)
#   sb-ipv6-leak.sh remove [каталог]            — убрать добавленный IPv6 из TUN (откат)
#   sb-ipv6-leak.sh test   config <файл> [порт] — сквозной тест через конфиг (mixed-инбаунд)
#   sb-ipv6-leak.sh test   proxy  <url>         — сквозной тест через готовый прокси
#                                                 (http://127.0.0.1:10808, socks5://127.0.0.1:1080)
#   sb-ipv6-leak.sh test   tun <файл> --yes     — тест в TUN-режиме (root; перехватывает
#                                                 ВЕСЬ трафик машины — только на VPS/тестовом стенде!)
#
# Переменные окружения:
#   SB_DIR     — каталог с конфигами (иначе аргумент или авто-поиск /var/www)
#   TUN_IPV6   — IPv6-CIDR для TUN (по умолчанию fdfe:dcba:9876::1/64)
#   BAK_ROOT   — каталог бэкапов (по умолчанию /root/bak-template)
#   SINGBOX_BIN — путь к sing-box (по умолчанию ищется в PATH)
#
# Патчится ТОЛЬКО TUN-инбаунд; остальная часть конфига не изменяется.
# Проверено на sing-box 1.14.x; формат — sing-box JSON.

set -euo pipefail

VERSION="1.0.0"
TUN_IPV6="${TUN_IPV6:-fdfe:dcba:9876::1/64}"
BAK_ROOT="${BAK_ROOT:-/root/bak-template}"
SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"
ECHO_V4="https://api.ipify.org"
ECHO_V6="https://api64.ipify.org"
ECHO_V6ONLY="http://v6.ident.me"

die()  { echo "ОШИБКА: $*" >&2; exit 1; }
info() { echo "$*"; }

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ---------- поиск конфигов ----------
# Все *.json с полем .inbounds (клиентские конфиги, шаблоны). Глубина 2 —
# этого хватает для каталогов вида /var/www/<секрет>/<файлы>.
find_configs() {
  local dir="${1:-${SB_DIR:-/var/www}}"
  [[ -d $dir ]] || die "каталог не найден: $dir"
  find "$dir" -maxdepth 2 -name '*.json' 2>/dev/null | sort | while read -r f; do
    jq -e '.inbounds' "$f" >/dev/null 2>&1 && echo "$f"
  done
}

# ---------- анализ одного файла ----------
# Вывод: notun | ok | leak|<описание>
analyze() {
  local f=$1
  jq -r '
    [.inbounds[]? | select(.type=="tun")] as $t |
    if ($t | length) == 0 then "notun"
    else
      ($t[0].address // []) as $a |
      ([$a[] | select(contains(":"))] | length) as $v6n |
      if $v6n == 0 then
        "leak|TUN без IPv6 (address: \($a | join(","))), auto_route: \($t[0].auto_route // false), strict_route: \($t[0].strict_route // false)"
      elif (($t[0].auto_route // false) | not) then
        "leak|auto_route: false — захвата маршрутов нет, трафик идёт мимо туннеля"
      elif (($t[0].strict_route // false) | not) then
        "warn|IPv6 есть, но strict_route: false — возможны обходные маршруты ОС"
      else "ok" end
    end' "$f"
}

dns_info() {
  local f=$1
  jq -r '[.dns.servers[]? | select(.detour == null)] | length' "$f" 2>/dev/null || echo "?"
}

# ---------- команды ----------
cmd_check() {
  info "=== sb-ipv6-leak check (v$VERSION) ==="
  local total=0 leak=0
  while read -r f; do
    [[ -n $f ]] || continue
    total=$((total + 1))
    local res; res=$(analyze "$f")
    local kind="${res%%|*}"
    case $kind in
      notun) info "  ➖ ${f##*/} — TUN-инбаунда нет (system proxy?), пропущен" ;;
      ok)    info "  ✅ ${f##*/} — OK (TUN захватывает IPv4+IPv6)" ;;
      warn)  info "  ⚠️  ${f##*/} — ${res#*|}" ;;
      leak)  info "  ❌ ${f##*/} — УТЕЧКА: ${res#*|}"; leak=$((leak + 1)) ;;
    esac
    local dn; dn=$(dns_info "$f")
    [[ $dn == 0 ]] || info "      (справочно: DNS-серверов без detour (системный резолвер): $dn — норма для правил direct)"
  done < <(find_configs "${1:-}")
  info "---"
  info "итого конфигов: $total, с утечкой: $leak"
  [[ $leak -eq 0 ]] || info "лечение: sb-ipv6-leak.sh patch [каталог]"
  return 0
}

cmd_status() {
  info "=== sb-ipv6-leak status (v$VERSION) ==="
  info "TUN_IPV6=$TUN_IPV6"
  local ok=0 leak=0 notun=0
  while read -r f; do
    [[ -n $f ]] || continue
    case "$(analyze "$f")" in
      ok|warn*) ok=$((ok + 1)) ;;
      leak*)    leak=$((leak + 1)) ;;
      *)        notun=$((notun + 1)) ;;
    esac
  done < <(find_configs "${1:-}")
  info "пропатчено (OK): $ok | с утечкой: $leak | без TUN: $notun"
}

cmd_patch() {
  local dir="${1:-${SB_DIR:-/var/www}}"
  local files=()
  while read -r f; do
    [[ -n $f ]] && [[ $(analyze "$f") == leak* ]] && files+=("$f")
  done < <(find_configs "$dir")
  [[ ${#files[@]} -gt 0 ]] || { info "пропатчивать нечего — утечек не найдено"; return 0; }

  local baks="$BAK_ROOT/leakfix-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$baks"
  local patched=0
  for f in "${files[@]}"; do
    cp -p "$f" "$baks/"
    jq --arg v6 "$TUN_IPV6" '
      .inbounds |= map(
        if .type == "tun" then
          .address = (((.address // []) + [$v6]) | unique)
          | .auto_route = true
          | .strict_route = true
        else . end)' "$f" > "$f.sbtmp"
    cat "$f.sbtmp" > "$f"   # перезапись содержимого = сохранение прав/владельца
    rm -f "$f.sbtmp"
    jq -e . "$f" >/dev/null 2>&1 || die "файл повреждён после патча: $f (бэкап: $baks)"
    if command -v "$SINGBOX_BIN" >/dev/null 2>&1; then
      "$SINGBOX_BIN" check -c "$f" >/dev/null 2>&1 \
        || info "  ⚠️ ${f##*/}: sing-box check не прошёл (JSON валиден; проверьте конфиг)"
    fi
    info "  ✅ пропатчен: ${f##*/}"
    patched=$((patched + 1))
  done
  info "---"
  info "пропатчено файлов: $patched"
  info "бэкап: $baks"
  info "клиентам: обновить подписку / переимпортировать конфиг"
}

cmd_remove() {
  local dir="${1:-${SB_DIR:-/var/www}}"
  local n=0
  while read -r f; do
    [[ -n $f ]] || continue
    if jq -e --arg v6 "$TUN_IPV6" '.inbounds[]? | select(.type=="tun") | (.address // []) | index($v6)' "$f" >/dev/null 2>&1; then
      jq --arg v6 "$TUN_IPV6" '
        .inbounds |= map(if .type=="tun" then .address = ((.address // []) - [$v6]) else . end)' \
        "$f" > "$f.sbtmp"
      cat "$f.sbtmp" > "$f"; rm -f "$f.sbtmp"
      jq -e . "$f" >/dev/null 2>&1 || die "файл повреждён: $f"
      info "  ↩ убран $TUN_IPV6 из: ${f##*/}"
      n=$((n + 1))
    fi
  done < <(find_configs "$dir")
  info "откат выполнен для файлов: $n (auto_route/strict_route не тронуты)"
}

# ---------- сквозной тест ----------
leak_verdict() {
  local px="$1"
  local d4 d6 t4 t6
  info "=== прямой выход (без туннеля) ==="
  d4=$(curl -4 -s -m 10 "$ECHO_V4" || echo "?")
  d6=$(curl -6 -s -m 10 "$ECHO_V6" || echo "?")
  info "  IPv4: $d4"
  info "  IPv6: ${d6:-нет}"
  info "=== через туннель ==="
  t4=$(curl ${px:+-x "$px"} -s -m 15 "$ECHO_V4" || echo "?")
  t6=$(curl ${px:+-x "$px"} -s -m 15 "$ECHO_V6ONLY" || echo "?")
  info "  IPv4-цели видят: $t4"
  info "  IPv6-only цель видит: $t6"
  info "---"
  local bad=0
  if [[ $t4 == "?" ]]; then
    info "⚠️ IPv4 через туннель: не удалось проверить"
  elif [[ -n $px && ( $t4 == "$d4" || $t4 == "$d6" ) ]]; then
    info "❌ УТЕЧКА IPv4: мир видит прямой IP ($t4)"; bad=1
  else
    info "✅ IPv4 идёт через туннель (видимый IP: $t4)"
  fi
  if [[ $t6 == "?" ]]; then
    info "⚠️ IPv6 через туннель: не удалось проверить (нет v6-egress у прокси/сервера?)"
  elif [[ -n $px && ( $t6 == "$d4" || $t6 == "$d6" ) ]]; then
    info "❌ УТЕЧКА IPv6: виден реальный IP ($t6)"; bad=1
  else
    info "✅ IPv6 идёт через туннель (видимый IP: $t6)"
  fi
  [[ $bad -eq 0 ]] || info "лечение: sb-ipv6-leak.sh patch + переимпорт конфига клиентом"
  return $bad
}

cmd_test() {
  local mode="${1:-}"; shift || true
  command -v curl >/dev/null 2>&1 || die "curl не найден"
  case "$mode" in
    proxy)
      [[ $# -ge 1 ]] || die "укажите URL прокси, например: test proxy http://127.0.0.1:10808"
      leak_verdict "$1"
      ;;
    config)
      [[ $# -ge 1 ]] || die "укажите файл конфига sing-box"
      command -v "$SINGBOX_BIN" >/dev/null 2>&1 || die "$SINGBOX_BIN не найден (нужен sing-box)"
      local cfg="$1" port="${2:-18080}"
      local tmpd; tmpd=$(mktemp -d)
      # mixed-инбаунд вместо TUN: не трогает маршруты машины; тег сохраняем,
      # чтобы правила DNS с match по inbound сработали как у клиента
      jq --arg p "$port" '
        .inbounds = [{"type":"mixed",
                      "tag": (.inbounds[0].tag // "tun-in"),
                      "listen":"127.0.0.1",
                      "listen_port": ($p | tonumber)}]' "$cfg" > "$tmpd/test.json"
      "$SINGBOX_BIN" check -c "$tmpd/test.json" >/dev/null || die "конфиг не прошёл sing-box check"
      "$SINGBOX_BIN" run -c "$tmpd/test.json" > "$tmpd/run.log" 2>&1 &
      local pid=$!
      trap 'kill $pid 2>/dev/null || true; rm -rf "$tmpd"' EXIT
      sleep 2
      kill -0 "$pid" 2>/dev/null || { tail -5 "$tmpd/run.log" >&2; die "sing-box не стартовал"; }
      leak_verdict "http://127.0.0.1:$port"
      ;;
    tun)
      [[ $# -ge 1 ]] || die "укажите файл конфига sing-box"
      [[ "${2:-}" == "--yes" ]] || die "TUN-режим перехватывает ВЕСЬ трафик машины. Запускать только на VPS/тестовом стенде. Для подтверждения: test tun <файл> --yes"
      command -v "$SINGBOX_BIN" >/dev/null 2>&1 || die "$SINGBOX_BIN не найден (нужен sing-box)"
      [[ $EUID -eq 0 ]] || die "TUN-режим требует root"
      local cfg="$1"
      "$SINGBOX_BIN" check -c "$cfg" >/dev/null || die "конфиг не прошёл sing-box check"
      "$SINGBOX_BIN" run -c "$cfg" > /tmp/sb-ipv6-leak-tun.log 2>&1 &
      local pid=$!
      trap 'kill $pid 2>/dev/null || true' EXIT
      sleep 3
      kill -0 "$pid" 2>/dev/null || { tail -5 /tmp/sb-ipv6-leak-tun.log >&2; die "sing-box не стартовал"; }
      leak_verdict ""
      ;;
    *)
      die "неизвестный режим теста: ${mode:-<пусто>} (config | proxy | tun)"
      ;;
  esac
}

# ---------- main ----------
case "${1:-}" in
  check)        cmd_check "${2:-}" ;;
  status)       cmd_status "${2:-}" ;;
  patch)        cmd_patch "${2:-}" ;;
  remove)       cmd_remove "${2:-}" ;;
  test)         shift; cmd_test "$@" ;;
  version|--version|-V) echo "sb-ipv6-leak v$VERSION" ;;
  help|--help|-h|"")    usage ;;
  *)            die "неизвестная команда: $1 (см. help)" ;;
esac
