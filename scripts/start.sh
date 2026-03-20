#!/bin/bash
set -euo pipefail

# ────────────────────────────────────────────────
# Основные переменные (все важное — в начале)
# ────────────────────────────────────────────────

LAN_ADDR="192.168.1.10"           # IP самого прокси-сервера в LAN
TPROXY_ADDR="0.0.0.0"           # куда TPROXY отправляет (обычно тот же IP)
TPROXY_PORT="1080"                # порт socks/http proxy (dante, 3proxy, shadowsocks и т.п.)

LAN_IFACE="eno1"                  # интерфейс локальной сети (откуда приходят клиенты)
OVPN_IFACE="tun0"                 # интерфейс OpenVPN (если есть)
OVPN_NET="172.14.0.0/24"

IPTV_ADDR="192.168.1.34"          # IPTV-устройство — полностью исключить

# Порты, которые хотим прозрачно проксировать (самое частое + мессенджеры)
PORTS_TCP="80,443,4433:4477,5222:5229,5060:5065,3478:3481,8443:8544,19302:19309"
PORTS_UDP="443,3478:3481,50000:65535"

# Порты, которые блокируем (DHT от торрентов)
TORRENT_PORTS="6771,6881:6999"

# ────────────────────────────────────────────────
# sysctl — минимальный и безопасный набор
# ────────────────────────────────────────────────

echo "[*] Настройка sysctl"
sysctl -w net.ipv4.ip_forward=1                          >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.src_valid_mark=1             >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.src_valid_mark=1	 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.rp_filter=0                  >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.rp_filter=0		 >/dev/null 2>&1
sysctl -w net.ipv4.conf.${LAN_IFACE}.rp_filter=0         >/dev/null 2>&1
sysctl -w net.ipv4.conf.${OVPN_IFACE}.rp_filter=0 	 >/dev/null 2>&1

# accept_local нужен редко — убираем, если не используешь
sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null 2>&1

# ────────────────────────────────────────────────
# Policy routing для TPROXY (маршрутизация помеченных пакетов в loopback)
# ────────────────────────────────────────────────

echo "[*] Настройка routing table 100 (TPROXY mark)"
ip rule  del fwmark 0x1           table 100  2>/dev/null || true
ip route flush table 100                     2>/dev/null || true
ip rule  add fwmark 0x1           lookup 100
ip route replace local 0.0.0.0/0  dev lo     table 100

# ────────────────────────────────────────────────
# Очистка старых цепочек
# ────────────────────────────────────────────────

echo "[*] Очистка и создание цепочек mangle"
iptables -t mangle -F
iptables -t mangle -X TPROXY_CHAIN  2>/dev/null || true
iptables -t mangle -X TPROXY_MARK   2>/dev/null || true
iptables -t mangle -N TPROXY_CHAIN
iptables -t mangle -N TPROXY_MARK

iptables -t nat -A POSTROUTING -j MASQUERADE

# ────────────────────────────────────────────────
# Блокировка торрент-DHT (раньше — выше приоритет)
# ────────────────────────────────────────────────

echo "[*] Блокировка Torrent DHT"
iptables -t mangle -I PREROUTING -p tcp -m multiport --dports "$TORRENT_PORTS" -j DROP
iptables -t mangle -I PREROUTING -p udp -m multiport --dports "$TORRENT_PORTS" -j DROP

# ────────────────────────────────────────────────
# TPROXY_CHAIN — только для входящего с LAN (самое важное)
# ────────────────────────────────────────────────

echo "[*] Настройка TPROXY_CHAIN (только LAN → proxy)"

# DoH/DoQ bypass: не трогаем QUIC к известным DNS-резолверам
iptables -t mangle -I TPROXY_CHAIN 1 -p udp --dport 443 -d 8.8.8.8 -j RETURN
iptables -t mangle -I TPROXY_CHAIN 1 -p tcp --dport 443 -d 8.8.8.8 -j RETURN
iptables -t mangle -I TPROXY_CHAIN 1 -p udp --dport 443 -d 1.1.1.1 -j RETURN
iptables -t mangle -I TPROXY_CHAIN 1 -p tcp --dport 443 -d 1.1.1.1 -j RETURN

# 1. Исключаем самого себя и IPTV
iptables -t mangle -A TPROXY_CHAIN -s "$LAN_ADDR"  -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d "$LAN_ADDR"  -j RETURN
iptables -t mangle -A TPROXY_CHAIN -s "$IPTV_ADDR" -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d "$IPTV_ADDR" -j RETURN

# 2. Исключаем служебное и приватные сети
iptables -t mangle -A TPROXY_CHAIN -p icmp          -j RETURN
iptables -t mangle -A TPROXY_CHAIN -p igmp          -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 0.0.0.0/8     -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 10.0.0.0/8    -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 127.0.0.0/8   -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 224.0.0.0/4   -j RETURN
iptables -t mangle -A TPROXY_CHAIN -d 240.0.0.0/4   -j RETURN

# 3. Защита от петель (уже помеченные + уже в сокете TPROXY)
iptables -t mangle -A TPROXY_CHAIN -m mark --mark 0x1       -j RETURN
iptables -t mangle -A TPROXY_CHAIN -m mark --mark 0x2       -j RETURN  # Skip proxy-originated outbound traffic
iptables -t mangle -A TPROXY_CHAIN -p tcp -m socket --transparent -j MARK --set-mark 0x1
iptables -t mangle -A TPROXY_CHAIN -p udp -m socket --transparent -j MARK --set-mark 0x1
iptables -t mangle -A TPROXY_CHAIN -m socket                -j RETURN

# 4. Сам TPROXY — только выбранные порты (HTTP/HTTPS + мессенджеры)
iptables -t mangle -A TPROXY_CHAIN -p tcp -m multiport --dports "$PORTS_TCP" -j TPROXY --on-port "$TPROXY_PORT" --on-ip "$TPROXY_ADDR" --tproxy-mark 0x1
iptables -t mangle -A TPROXY_CHAIN -p udp -m multiport --dports "$PORTS_UDP" -j TPROXY --on-port "$TPROXY_PORT" --on-ip "$TPROXY_ADDR" --tproxy-mark 0x1

# Привязываем только к LAN-интерфейсу (важно при VPN!)
iptables -t mangle -A PREROUTING -i "$LAN_IFACE" -j TPROXY_CHAIN
iptables -t mangle -A PREROUTING -i "$OVPN_IFACE" -j TPROXY_CHAIN

# ────────────────────────────────────────────────
# TPROXY_MARK — для локального трафика с самого сервера
# ────────────────────────────────────────────────

echo "[*] Настройка TPROXY_MARK (локальный исходящий трафик)"
iptables -t mangle -A TPROXY_MARK -s "$LAN_ADDR"  -j RETURN
iptables -t mangle -A TPROXY_MARK -d "$LAN_ADDR"  -j RETURN
iptables -t mangle -A TPROXY_MARK -s "$IPTV_ADDR" -j RETURN
iptables -t mangle -A TPROXY_MARK -d "$IPTV_ADDR" -j RETURN

# DoH/DoQ bypass: не трогаем QUIC к известным DNS-резолверам
iptables -t mangle -I TPROXY_MARK 1 -p udp --dport 443 -d 8.8.8.8 -j RETURN
iptables -t mangle -I TPROXY_MARK 1 -p tcp --dport 443 -d 8.8.8.8 -j RETURN
iptables -t mangle -I TPROXY_MARK 1 -p udp --dport 443 -d 1.1.1.1 -j RETURN
iptables -t mangle -I TPROXY_MARK 1 -p tcp --dport 443 -d 1.1.1.1 -j RETURN

# Prevent loop
iptables -t mangle -A TPROXY_MARK -m mark --mark 0x1       -j RETURN
iptables -t mangle -A TPROXY_MARK -m mark --mark 0x2       -j RETURN  # Skip proxy-originated outbound traffic

# Исключаем приватные сети (как выше)
iptables -t mangle -A TPROXY_MARK -d 10.0.0.0/8     -j RETURN
iptables -t mangle -A TPROXY_MARK -d 127.0.0.0/8    -j RETURN
iptables -t mangle -A TPROXY_MARK -d 172.16.0.0/12  -j RETURN
iptables -t mangle -A TPROXY_MARK -d 192.168.0.0/16 -j RETURN

# Маркируем только выбранные порты (или весь TCP/UDP — закомментировано)
iptables -t mangle -A TPROXY_MARK -p tcp -m multiport --dports "$PORTS_TCP" -j MARK --set-mark 0x1
iptables -t mangle -A TPROXY_MARK -p udp -m multiport --dports "$PORTS_UDP" -j MARK --set-mark 0x1

# Если хочешь весь трафик с сервера — раскомментируй и добавь исключения
# iptables -t mangle -A TPROXY_MARK -p tcp -j MARK --set-mark 0x1
# iptables -t mangle -A TPROXY_MARK -p udp -j MARK --set-mark 0x1

iptables -t mangle -A OUTPUT -j TPROXY_MARK

echo "[*] Готово! Правила загружены."
echo "Проверь: iptables -t mangle -nvL | grep -C2 TPROXY"
echo "         ss -ltnp | grep :$TPROXY_PORT"