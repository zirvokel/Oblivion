#!/usr/bin/env bash
set -Eeuo pipefail

IP_DOM1="192.168.10.1/24"
IP_DOM2="10.10.240.1/24"

DOM1_DC_IP="192.168.10.2"
DOM2_DC_IP="10.10.240.2"
SHARE="Transactions"

DOM1_USER="svc_relay_dom1"
DOM2_USER="svc_relay_dom2"
DOM1_PASS="Luglio11"
DOM2_PASS="Luglio11"
DOM1_DOMAIN="DOM1"
DOM2_DOMAIN="DOM2"

MNT1="/mnt/dom1_transactions"
MNT2="/mnt/dom2_transactions"
LOGDIR="/var/log/ftbridge"
LOGFILE="$LOGDIR/sync.log"

SERVICE_NAME="ftbridge-sync.service"
TIMER_NAME="ftbridge-sync.timer"

say(){ echo -e "$*"; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; }

pick_ifaces() {
  local i1="${IFACE_DOM1:-}" i2="${IFACE_DOM2:-}"
  if [[ -z "$i1" || -z "$i2" ]]; then
    echo "Interfaces détectées :"
    ip -o link show | awk -F': ' '$2!="lo"{print "  - "$2" (MAC " $2 ")"}' | sed 's/ (MAC \(.*\))/ (MAC '"$(for i in /sys/class/net/*/address; do printf "%s " "$(cat "$i")"; done)"')/; s/ .*//'
    read -rp "Interface DOM1 (ex: enp0s3) : " i1
    read -rp "Interface DOM2 (ex: enp0s8) : " i2
  fi
  IFACE_DOM1="$i1"
  IFACE_DOM2="$i2"
}

config_ips() {
  say "=== 1) Réseau (iproute2) ==="
  ip -4 addr show dev "$IFACE_DOM1" | grep -q "${IP_DOM1%/*}" || ip addr add "$IP_DOM1" dev "$IFACE_DOM1"
  ip link set "$IFACE_DOM1" up
  ip -4 addr show dev "$IFACE_DOM2" | grep -q "${IP_DOM2%/*}" || ip addr add "$IP_DOM2" dev "$IFACE_DOM2"
  ip link set "$IFACE_DOM2" up

  ip -4 addr show "$IFACE_DOM1" | sed -n 's/.*inet \(.*\) scope.*/    \1 '"$IFACE_DOM1"'/p'
  ip -4 addr show "$IFACE_DOM2" | sed -n 's/.*inet \(.*\) scope.*/    \1 '"$IFACE_DOM2"'/p'

  say "=== 1b) Anti-routage ==="
  sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null
  echo "net.ipv4.ip_forward=0" >/etc/sysctl.d/99-relay-noroute.conf
}

install_pkgs() {
  say "=== 2) Paquets ==="
  apt-get update -y || true
  apt-get install -y --no-install-recommends cifs-utils rsync smbclient
  mkdir -p "$MNT1" "$MNT2" "$LOGDIR"
  umask 077
}

write_creds() {
  install -m 600 /dev/null /root/.cred_dom1
  cat >/root/.cred_dom1 <<EOF
username=$DOM1_USER
password=$DOM1_PASS
domain=$DOM1_DOMAIN
EOF

  install -m 600 /dev/null /root/.cred_dom2
  cat >/root/.cred_dom2 <<EOF
username=$DOM2_USER
password=$DOM2_PASS
domain=$DOM2_DOMAIN
EOF
}

setup_fstab_and_mounts() {
  say "=== 3) fstab + montages ==="
  awk '!($2=="/mnt/dom1_transactions" || $2=="/mnt/dom2_transactions")' /etc/fstab > /tmp/fstab.new \
    && cat /tmp/fstab.new > /etc/fstab && rm -f /tmp/fstab.new

  cat >>/etc/fstab <<EOF
//$DOM1_DC_IP/$SHARE $MNT1 cifs credentials=/root/.cred_dom1,vers=3.0,sec=ntlmssp,uid=0,gid=0,file_mode=0640,dir_mode=0750,soft,noperm 0 0
//$DOM2_DC_IP/$SHARE $MNT2 cifs credentials=/root/.cred_dom2,vers=3.0,sec=ntlmssp,uid=0,gid=0,file_mode=0640,dir_mode=0750,soft,noperm 0 0
EOF

  sudo systemctl daemon-reload || true
  sudo mount -a || true
  echo "Montages actifs :"
  sudo mount | grep -E "$MNT1|$MNT2" || echo "  (pas encore monté)"
}

install_sync_script() {
  say "=== 4) Script de synchronisation (bi-directionnel) ==="
  cat >/usr/local/sbin/ftbridge_sync.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/ftbridge/sync.log"
DOM1="/mnt/dom1_transactions"
DOM2="/mnt/dom2_transactions"
LOCK="/run/ftbridge.sync.lock"

log(){ printf "[%(%F %T)T] %s\n" -1 "$*" >>"$LOG"; }

map_to_dom2(){
  local u="$1"
  if [[ "$u" == *".dmz" ]];    then echo "${u%.dmz}.adm";  return; fi
  if [[ "$u" == *"_in"  ]];   then echo "${u%_in}_out";    return; fi
  echo "$u"
}
map_to_dom1(){
  local u="$1"
  if [[ "$u" == *".adm" ]];    then echo "${u%.adm}.dmz";  return; fi
  if [[ "$u" == *"_out" ]];   then echo "${u%_out}_in";    return; fi
  echo "$u"
}

ensure_mount() {
  local p="$1"
  if ! mountpoint -q "$p"; then
    log "Montage absent: $p -> tentative mount"
    mount "$p" 2>>"$LOG" || { log "Échec mount $p"; return 1; }
  fi
  return 0
}

stable_push() {
  local src="$1" dst="$2"
  [[ -d "$src" ]] || return 0
  mkdir -p "$dst"
  shopt -s nullglob
  local moved=0
  for f in "$src"/*; do
    [[ -f "$f" ]] || continue
    local s1 s2
    s1=$(stat -c%s "$f" 2>/dev/null || echo -1)
    sleep 2
    s2=$(stat -c%s "$f" 2>/dev/null || echo -2)
    if [[ "$s1" -ne "$s2" || "$s1" -lt 0 ]]; then
      log "Skip (instable): $f"
      continue
    fi
    moved=1
  done
  rsync -rt --partial --partial-dir=.rsync-partial --remove-source-files "$src/" "$dst/" >>"$LOG" 2>&1 || true
  return $moved
}

main() {
  exec 9>"$LOCK" || exit 0
  if ! flock -n 9; then
    log "Run déjà en cours, on saute."
    exit 0
  fi

  ensure_mount "$DOM1" || exit 0
  ensure_mount "$DOM2" || exit 0

  log "=== CYCLE ==="

  while IFS= read -r -d '' uroot; do
    u="$(basename "$uroot")"
    [[ -d "$uroot/IN" ]] || { log "DOM1: $u sans IN, skip"; continue; }
    v="$(map_to_dom2 "$u")"
    dst="$DOM2/$v/OUT"
    log "DOM1->DOM2 : $u/IN -> $v/OUT"
    stable_push "$uroot/IN" "$dst" || true
  done < <(find "$DOM1" -mindepth 1 -maxdepth 1 -type d -print0)

  while IFS= read -r -d '' vroot; do
    v="$(basename "$vroot")"
    [[ -d "$vroot/IN" ]] || { log "DOM2: $v sans IN, skip"; continue; }
    u="$(map_to_dom1 "$v")"
    dst="$DOM1/$u/OUT"
    log "DOM2->DOM1 : $v/IN -> $u/OUT"
    stable_push "$vroot/IN" "$dst" || true
  done < <(find "$DOM2" -mindepth 1 -maxdepth 1 -type d -print0)
}

main
EOF
  chmod +x /usr/local/sbin/ftbridge_sync.sh
  : > "$LOGFILE"
}

install_systemd_timer() {
  say "=== 5) Service + Timer systemd (10s) ==="

  cat >/etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=FTBridge sync bi-directionnelle (IN->OUT) DOM1<->DOM2
After=network-online.target remote-fs.target
Wants=network-online.target
RequiresMountsFor=$MNT1 $MNT2

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ftbridge_sync.sh
Nice=10
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/$TIMER_NAME <<EOF
[Unit]
Description=Planification FTBridge sync (~10s)

[Timer]
OnBootSec=15s
OnUnitActiveSec=10s
AccuracySec=1s
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF

  sudo systemctl daemon-reload
  sudo systemctl enable --now $TIMER_NAME
}

need_root
pick_ifaces
config_ips
install_pkgs
write_creds
setup_fstab_and_mounts
install_sync_script
install_systemd_timer

say "=== OK ===
- Interfaces : DOM1=$IFACE_DOM1 ($IP_DOM1) / DOM2=$IFACE_DOM2 ($IP_DOM2)
- Montages   : $MNT1 et $MNT2 (fstab)
- Script     : /usr/local/sbin/ftbridge_sync.sh
- Logs       : $LOGFILE
- Service    : $SERVICE_NAME
- Timer      : $TIMER_NAME (toutes ~10s, auto au boot)
"