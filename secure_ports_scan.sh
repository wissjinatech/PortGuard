#!/usr/bin/env bash

set -Eeuo pipefail

# ===========================
#  PortGuard — Anti-scan + ACL
# ===========================
# Menu:
# 1) Appliquer la sécurité (avec configuration manuelle au besoin)
# 2) Ajouter IP à la whitelist
# 3) Ajouter IP à la blacklist
# 4) Afficher whitelist & config (ports TCP/UDP, paramètres)
# 5) Afficher blacklist
#
# Persistance:
# - ipset restauré par systemd (ipset-restore.service)
# - iptables sauvegardé via netfilter-persistent (si dispo) sinon service custom
#
# Défaults (modifiables au choix 1) :
CFG_FILE="/etc/portguard.conf"
: "${ALLOWED_TCP_DEF:="22 80 443 8080 8443 888 8888"}"
: "${ALLOWED_UDP_DEF:="53"}"
: "${BAN_SECONDS_DEF:=86400}"
: "${DETECT_WINDOW_DEF:=30}"
: "${TCP_HITCOUNT_DEF:=3}"
: "${UDP_HITCOUNT_DEF:=5}"
: "${ICMP_HITCOUNT_DEF:=10}"
: "${CHAIN_DEF:=PORTGUARD}"
: "${WL_SET_DEF:=whitelist}"
: "${BL_SET_DEF:=blacklist}"

ROOT_REQ() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[-] Exécute en root (sudo)"; exit 1
  fi
}

HAS() { command -v "$1" >/dev/null 2>&1; }

PKG_INSTALL() {
  local pkgs=("$@")
  if HAS apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${pkgs[@]}" >/dev/null 2>&1 || true
  elif HAS dnf; then
    dnf -y install "${pkgs[@]}" >/dev/null 2>&1 || true
  elif HAS yum; then
    yum -y install "${pkgs[@]}" >/dev/null 2>&1 || true
  elif HAS zypper; then
    zypper -n in "${pkgs[@]}" >/dev/null 2>&1 || true
  else
    echo "[-] Gestionnaire de paquets non supporté. Installe manuellement: ${pkgs[*]}"; return 1
  fi
}

ENSURE_DEPS() {
  echo "[*] Vérification dépendances…"
  HAS ipset || PKG_INSTALL ipset
  if ! HAS iptables; then
    PKG_INSTALL iptables || true
  fi
  # netfilter-persistent (Debian/Ubuntu) pour restaurer iptables
  if HAS apt-get && ! HAS netfilter-persistent; then
    PKG_INSTALL iptables-persistent netfilter-persistent || true
  fi
}

SAVE_IPSET() { ipset save > /etc/ipset.conf; }

ENSURE_IPSET_SERVICE() {
cat >/etc/systemd/system/ipset-restore.service <<'UNIT'
[Unit]
Description=Restore ipset sets at boot
Before=netfilter-persistent.service iptables-restore.service
Wants=netfilter-persistent.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/ipset restore < /etc/ipset.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now ipset-restore.service >/dev/null 2>&1 || true
}

ENSURE_IPTABLES_PERSIST() {
  if HAS netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 || true
    return
  fi
  # Service custom iptables-restore si netfilter-persistent absent
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4
cat >/etc/systemd/system/iptables-restore.service <<'UNIT'
[Unit]
Description=Restore iptables rules at boot (IPv4)
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore < /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now iptables-restore.service >/dev/null 2>&1 || true
}

WRITE_CFG() {
  cat > "$CFG_FILE" <<EOF
# PortGuard configuration
ALLOWED_TCP="${ALLOWED_TCP}"
ALLOWED_UDP="${ALLOWED_UDP}"
BAN_SECONDS=${BAN_SECONDS}
DETECT_WINDOW=${DETECT_WINDOW}
TCP_HITCOUNT=${TCP_HITCOUNT}
UDP_HITCOUNT=${UDP_HITCOUNT}
ICMP_HITCOUNT=${ICMP_HITCOUNT}
CHAIN="${CHAIN}"
WL_SET="${WL_SET}"
BL_SET="${BL_SET}"
EOF
  chmod 600 "$CFG_FILE"
}

LOAD_CFG() {
  if [ -f "$CFG_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CFG_FILE"
  else
    ALLOWED_TCP="$ALLOWED_TCP_DEF"
    ALLOWED_UDP="$ALLOWED_UDP_DEF"
    BAN_SECONDS="$BAN_SECONDS_DEF"
    DETECT_WINDOW="$DETECT_WINDOW_DEF"
    TCP_HITCOUNT="$TCP_HITCOUNT_DEF"
    UDP_HITCOUNT="$UDP_HITCOUNT_DEF"
    ICMP_HITCOUNT="$ICMP_HITCOUNT_DEF"
    CHAIN="$CHAIN_DEF"
    WL_SET="$WL_SET_DEF"
    BL_SET="$BL_SET_DEF"
  fi
}

PROMPT_YN() { # $1=question $2=default(Y/N)
  local q="$1" def="${2:-Y}" ans
  read -rp "$q [${def}/n]: " ans || true
  ans="${ans:-$def}"; [[ "$ans" =~ ^[Yy]$ ]]
}

CONFIGURE_INTERACTIVE() {
  echo "=== Configuration PortGuard ==="
  echo "(laisser vide pour garder la valeur par défaut)"
  read -rp "Ports TCP autorisés (espace): [$ALLOWED_TCP] " tmp || true
  [[ -n "${tmp:-}" ]] && ALLOWED_TCP="$tmp"
  read -rp "Ports UDP autorisés (espace): [$ALLOWED_UDP] " tmp || true
  [[ -n "${tmp:-}" ]] && ALLOWED_UDP="$tmp"
  read -rp "BAN_SECONDS (durée ban, s): [$BAN_SECONDS] " tmp || true
  [[ -n "${tmp:-}" ]] && BAN_SECONDS="$tmp"
  read -rp "DETECT_WINDOW (fenêtre, s): [$DETECT_WINDOW] " tmp || true
  [[ -n "${tmp:-}" ]] && DETECT_WINDOW="$tmp"
  read -rp "TCP_HITCOUNT: [$TCP_HITCOUNT] " tmp || true
  [[ -n "${tmp:-}" ]] && TCP_HITCOUNT="$tmp"
  read -rp "UDP_HITCOUNT: [$UDP_HITCOUNT] " tmp || true
  [[ -n "${tmp:-}" ]] && UDP_HITCOUNT="$tmp"
  read -rp "ICMP_HITCOUNT: [$ICMP_HITCOUNT] " tmp || true
  [[ -n "${tmp:-}" ]] && ICMP_HITCOUNT="$tmp"
  read -rp "Nom de chaîne iptables: [$CHAIN] " tmp || true
  [[ -n "${tmp:-}" ]] && CHAIN="$tmp"
  read -rp "Nom set whitelist: [$WL_SET] " tmp || true
  [[ -n "${tmp:-}" ]] && WL_SET="$tmp"
  read -rp "Nom set blacklist: [$BL_SET] " tmp || true
  [[ -n "${tmp:-}" ]] && BL_SET="$tmp"

  if PROMPT_YN "Ajouter des IP à la whitelist maintenant ?" "Y"; then
    echo "Saisis des IP séparées par des espaces (ou vide):"
    read -rp "IP: " WL_INIT || true
  else
    WL_INIT=""
  fi
  WRITE_CFG
}

STRING_TO_MULTI() { # convert "1 2 3" -> "1,2,3"
  echo "$1" | awk '{$1=$1; gsub(/ /,","); print}'
}

ENSURE_BASESETS() {
  ipset create "$WL_SET" hash:ip -exist
  ipset create "$BL_SET" hash:ip timeout "$BAN_SECONDS" -exist
}

APPLY_SECURITY() {
  ENSURE_DEPS
  LOAD_CFG
  if PROMPT_YN "Configurer manuellement ports/paramètres ?" "Y"; then
    CONFIGURE_INTERACTIVE
  fi
  ENSURE_BASESETS

  # Charger whitelist initiale si fournie
  if [[ -n "${WL_INIT:-}" ]]; then
    for ip in $WL_INIT; do
      ipset add "$WL_SET" "$ip" -exist
      ipset del "$BL_SET" "$ip" 2>/dev/null || true
    done
  fi

  # Chaîne et hook
  iptables -N "$CHAIN" 2>/dev/null || true
  iptables -F "$CHAIN"
  iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"

  # Règles (ordre important)
  # 0) Whitelist puis Blacklist
  iptables -C "$CHAIN" -m set --match-set "$WL_SET" src -j RETURN 2>/dev/null || \
    iptables -I "$CHAIN" 1 -m set --match-set "$WL_SET" src -j RETURN
  iptables -A "$CHAIN" -m set --match-set "$BL_SET" src -j DROP

  # 1) Hygiène
  iptables -A "$CHAIN" -i lo -j RETURN
  iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -A "$CHAIN" -m conntrack --ctstate INVALID -j DROP

  # 2) Autoriser ports
  local TCP_LIST UDP_LIST
  TCP_LIST="$(STRING_TO_MULTI "$ALLOWED_TCP")"
  UDP_LIST="$(STRING_TO_MULTI "$ALLOWED_UDP")"
  [[ -n "$ALLOWED_TCP" ]] && iptables -A "$CHAIN" -p tcp -m multiport --dports "$TCP_LIST" -m conntrack --ctstate NEW -j RETURN
  [[ -n "$ALLOWED_UDP" ]] && iptables -A "$CHAIN" -p udp -m multiport --dports "$UDP_LIST" -m conntrack --ctstate NEW -j RETURN

  # 3) Détection scans TCP hors-liste -> ban
  if [[ -n "$ALLOWED_TCP" ]]; then
    iptables -A "$CHAIN" -p tcp --syn -m multiport ! --dports "$TCP_LIST" \
             -m recent --name psdetect --update --seconds "$DETECT_WINDOW" --hitcount "$TCP_HITCOUNT" \
             -j SET --add-set "$BL_SET" src
    iptables -A "$CHAIN" -p tcp --syn -m multiport ! --dports "$TCP_LIST" \
             -m recent --name psdetect --set -j DROP
  else
    iptables -A "$CHAIN" -p tcp --syn \
             -m recent --name psdetect --update --seconds "$DETECT_WINDOW" --hitcount "$TCP_HITCOUNT" \
             -j SET --add-set "$BL_SET" src
    iptables -A "$CHAIN" -p tcp --syn -m recent --name psdetect --set -j DROP
  fi

  # 4) UDP
  if [[ -n "$ALLOWED_UDP" ]]; then
    iptables -A "$CHAIN" -p udp -m multiport ! --dports "$UDP_LIST" \
             -m recent --name psdetect --update --seconds "$DETECT_WINDOW" --hitcount "$UDP_HITCOUNT" \
             -j SET --add-set "$BL_SET" src
    iptables -A "$CHAIN" -p udp -m multiport ! --dports "$UDP_LIST" \
             -m recent --name psdetect --set -j DROP
  else
    iptables -A "$CHAIN" -p udp \
             -m recent --name psdetect --update --seconds "$DETECT_WINDOW" --hitcount "$UDP_HITCOUNT" \
             -j SET --add-set "$BL_SET" src
    iptables -A "$CHAIN" -p udp -m recent --name psdetect --set -j DROP
  fi

  # 5) Scans furtifs -> ban immédiat
  iptables -A "$CHAIN" -p tcp --tcp-flags ALL NONE        -j SET --add-set "$BL_SET" src
  iptables -A "$CHAIN" -p tcp --tcp-flags ALL FIN,URG,PSH -j SET --add-set "$BL_SET" src
  iptables -A "$CHAIN" -p tcp --tcp-flags SYN,FIN SYN,FIN -j SET --add-set "$BL_SET" src
  iptables -A "$CHAIN" -p tcp --tcp-flags SYN,RST SYN,RST -j SET --add-set "$BL_SET" src

  # 6) ICMP rapide -> ban
  iptables -A "$CHAIN" -p icmp \
           -m recent --name psdetect --update --seconds "$DETECT_WINDOW" --hitcount "$ICMP_HITCOUNT" \
           -j SET --add-set "$BL_SET" src
  iptables -A "$CHAIN" -p icmp -m recent --name psdetect --set -j DROP

  # 7) Fin
  iptables -A "$CHAIN" -j RETURN

  # Persistance
  SAVE_IPSET
  ENSURE_IPSET_SERVICE
  ENSURE_IPTABLES_PERSIST

  echo "[OK] Sécurité appliquée."
}

ADD_WL() {
  LOAD_CFG; ENSURE_DEPS; ENSURE_BASESETS
  local ips
  read -rp "IP à ajouter à la whitelist (séparées par espace): " ips || true
  for ip in $ips; do
    ipset add "$WL_SET" "$ip" -exist
    ipset del "$BL_SET" "$ip" 2>/dev/null || true
    echo "[+] WL: $ip"
  done
  SAVE_IPSET
  echo "[OK] Whitelist mise à jour."
}

ADD_BL() {
  LOAD_CFG; ENSURE_DEPS; ENSURE_BASESETS
  local ips
  read -rp "IP à ajouter à la blacklist (séparées par espace): " ips || true
  for ip in $ips; do
    ipset add "$BL_SET" "$ip" -exist
    echo "[+] BL: $ip"
  done
  SAVE_IPSET
  echo "[OK] Blacklist mise à jour."
}

SHOW_INFO() {
  LOAD_CFG
  echo "===== PortGuard: configuration ====="
  echo "CHAIN=$CHAIN | WL_SET=$WL_SET | BL_SET=$BL_SET"
  echo "ALLOWED_TCP=[$ALLOWED_TCP]"
  echo "ALLOWED_UDP=[$ALLOWED_UDP]"
  echo "BAN_SECONDS=$BAN_SECONDS | DETECT_WINDOW=$DETECT_WINDOW"
  echo "TCP_HITCOUNT=$TCP_HITCOUNT | UDP_HITCOUNT=$UDP_HITCOUNT | ICMP_HITCOUNT=$ICMP_HITCOUNT"
  echo
  echo "[*] Whitelist:"
  if ipset list "$WL_SET" >/dev/null 2>&1; then
    ipset list "$WL_SET"
  else
    echo "(set inexistant)"
  fi
}

SHOW_BL() {
  LOAD_CFG
  echo "[*] Blacklist:"
  if ipset list "$BL_SET" >/dev/null 2>&1; then
    ipset list "$BL_SET"
  else
    echo "(set inexistant)"
  fi
}

MENU() {
  echo "============================="
  echo "   PortGuard - Anti-scan"
  echo "============================="
  echo "1) Appliquer la sécurité"
  echo "2) Ajouter IP à la whitelist"
  echo "3) Ajouter IP à la blacklist"
  echo "4) Afficher whitelist & config"
  echo "5) Afficher blacklist"
  echo "0) Quitter"
  read -rp "Choix: " c || true
  case "${c:-}" in
    1) APPLY_SECURITY ;;
    2) ADD_WL ;;
    3) ADD_BL ;;
    4) SHOW_INFO ;;
    5) SHOW_BL ;;
    0) exit 0 ;;
    *) echo "Choix invalide";;
  esac
}

main() {
  ROOT_REQ
  ENSURE_DEPS
  while true; do
    MENU
    echo
  done
}

main "$@"
