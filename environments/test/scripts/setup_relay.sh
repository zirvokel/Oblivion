#!/usr/bin/env bash
set -Eeuo pipefail

# ==================== Paramètres à adapter si besoin ====================
IP_DOM1="192.168.10.1/24"
IP_DOM2="10.10.240.1/24"

DOM1_DC_IP="192.168.10.2"
DOM2_DC_IP="10.10.240.2"
SHARE="Transactions"

DOM1_USER="svc_relay_dom1"
DOM2_USER="svc_relay_dom2"
DOM1_DOMAIN="DOM1"
DOM2_DOMAIN="DOM2"

# Points de montage & chemins
MNT1="/mnt/dom1_transactions"
MNT2="/mnt/dom2_transactions"
LOGDIR="/var/log/ftbridge"
LOGFILE="$LOGDIR/sync.log"
QUAR_DIR="/var/quarantine/ftbridge"
MAP_DIR="/etc/ftbridge"
MAP_FILE="$MAP_DIR/map.csv"

SERVICE_NAME="ftbridge-sync.service"
TIMER_NAME="ftbridge-sync.timer"
NFT_CONF="/etc/nftables.d/99-ftbridge-drop-forward.nft"

# ==================== Fonctions utilitaires ====================
say(){ echo -e "$*"; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "Exécuter en root"; exit 1; }; }
prompt_secret(){ local prompt="$1" var; read -r -s -p "$prompt : " var; echo; printf "%s" "$var"; }

pick_ifaces() {
  local i1="${IFACE_DOM1:-}" i2="${IFACE_DOM2:-}"
  if [[ -z "$i1" || -z "$i2" ]]; then
    echo "Interfaces détectées :"
    ip -o link show | awk -F': ' '$2!="lo"{print "  - "$2}'
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
  sysctl -w net.ipv4.ip_forward=0 >/dev/null
  echo "net.ipv4.ip_forward=0" >/etc/sysctl.d/99-relay-noroute.conf

  # Pare-feu: DROP FORWARD (nftables)
  say "=== 2b) Pare-feu (nftables) : DROP du forward ==="
  mkdir -p /etc/nftables.d
  cat >"$NFT_CONF" <<'EOF'
table inet ftbridge_drop_fwd {
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
}
EOF
  systemctl enable --now nftables >/dev/null 2>&1 || true
  nft -f "$NFT_CONF" || true
}

install_pkgs() {
  say "=== 2) Paquets ==="
  apt-get update -y || true
  apt-get install -y --no-install-recommends \
    cifs-utils rsync smbclient coreutils util-linux psmisc \
    clamav clamav-freshclam clamav-daemon nftables

  mkdir -p "$MNT1" "$MNT2" "$LOGDIR" "$QUAR_DIR" "$MAP_DIR"
  chmod 700 "$QUAR_DIR"
  umask 077

  # Signatures ClamAV
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  freshclam --stdout || true
  systemctl enable --now clamav-freshclam >/dev/null 2>&1 || true
}

collect_creds() {
  local p1 p2
  p1="$(prompt_secret "Mot de passe ${DOM1_DOMAIN}\\${DOM1_USER}")"
  p2="$(prompt_secret "Mot de passe ${DOM2_DOMAIN}\\${DOM2_USER}")"

  install -m 600 /dev/null /root/.cred_dom1
  cat >/root/.cred_dom1 <<EOF
username=$DOM1_USER
password=$p1
domain=$DOM1_DOMAIN
EOF

  install -m 600 /dev/null /root/.cred_dom2
  cat >/root/.cred_dom2 <<EOF
username=$DOM2_USER
password=$p2
domain=$DOM2_DOMAIN
EOF
}

setup_fstab_and_mounts() {
  say "=== 3) fstab + montages ==="
  # Purge entrées existantes pour éviter les doublons
  awk '!($2=="/mnt/dom1_transactions" || $2=="/mnt/dom2_transactions")' /etc/fstab > /tmp/fstab.new \
    && cat /tmp/fstab.new > /etc/fstab && rm -f /tmp/fstab.new

  # Montages SMB (3.1.1 + seal, noexec/nosuid/nodev)
  cat >>/etc/fstab <<EOF
//$DOM1_DC_IP/$SHARE $MNT1 cifs credentials=/root/.cred_dom1,vers=3.1.1,sec=ntlmssp,uid=0,gid=0,file_mode=0640,dir_mode=0750,soft,noperm,nosuid,nodev,noexec,seal,actimeo=1 0 0
//$DOM2_DC_IP/$SHARE $MNT2 cifs credentials=/root/.cred_dom2,vers=3.1.1,sec=ntlmssp,uid=0,gid=0,file_mode=0640,dir_mode=0750,soft,noperm,nosuid,nodev,noexec,seal,actimeo=1 0 0
EOF

  systemctl daemon-reload || true
  mount -a || true
  echo "Montages actifs :"
  mount | grep -E "$MNT1|$MNT2" || echo "  (pas encore monté)"
}

install_ftbridge_sync() {
  say "=== 4) Script de synchronisation (écriture) ==="
  cat >/usr/local/sbin/ftbridge_sync.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

LOG="/var/log/ftbridge/sync.log"
DOM1="/mnt/dom1_transactions"
DOM2="/mnt/dom2_transactions"
LOCK="/run/ftbridge.sync.lock"
MAP_FILE="/etc/ftbridge/map.csv"
QUARANTINE_DIR="/var/quarantine/ftbridge"
LOG_LEVEL="${LOG_LEVEL:-INFO}"   # DEBUG|INFO|WARN|ERROR
RSYNC_PARTIAL_DIR=".rsync-partial"

CLAMSCAN_BIN="${CLAMSCAN_BIN:-/usr/bin/clamscan}"
REPORT_SUFFIX="_clamav"

_lvl_num(){ case "${1^^}" in DEBUG) echo 10;; INFO) echo 20;; WARN) echo 30;; ERROR) echo 40;; *) echo 20;; esac; }
_should_log(){ [[ $(_lvl_num "$1") -ge $(_lvl_num "$LOG_LEVEL") ]]; }
log(){ local lvl="${1:-INFO}"; shift || true; _should_log "$lvl" || return 0; printf "[%(%F %T)T] %-5s pid=%s %s\n" -1 "${lvl^^}" "$$" "$*" >>"$LOG"; }
log_kv(){ local lvl="${1:-INFO}"; shift; _should_log "$lvl" || return 0; printf "[%(%F %T)T] %-5s pid=%s " -1 "${lvl^^}" "$$" >>"$LOG"; printf "%s=%q " "$@" >>"$LOG"; printf "\n" >>"$LOG"; }
trap 'rc=$?; log ERROR "erreur inattendue (rc=$rc) à la ligne $LINENO"' ERR

# ------------ Mapping (CSV) ------------
# En-tête attendu: dom1_user,dom2_user,dom1_dir,dom2_dir
declare -A MAP_D1_TO_D2
declare -A MAP_D2_TO_D1
MAP_MTIME=0
load_map(){
  [[ -f "$MAP_FILE" ]] || { : > "$MAP_FILE"; }
  local mtime
  mtime=$(stat -c %Y "$MAP_FILE" 2>/dev/null || echo 0)
  [[ "$mtime" -eq "$MAP_MTIME" ]] && return 0
  MAP_D1_TO_D2=(); MAP_D2_TO_D1=()
  while IFS=, read -r d1 d2 d1dir d2dir; do
    [[ -z "${d1// }" || "${d1:0:1}" == "#" ]] && continue
    # Ignore l'en-tête s'il est présent (case-insensitive)
    shopt -s nocasematch
    if [[ "$d1" == "dom1_user" && "$d2" == "dom2_user" ]]; then shopt -u nocasematch; continue; fi
    shopt -u nocasematch
    # Normalisation (refuse suffixes dans la map)
    d1="${d1%%.dmz}"; d1="${d1%%.adm}"
    d2="${d2%%.dmz}"; d2="${d2%%.adm}"
    d1="${d1#"${d1%%[![:space:]]*}"}"; d1="${d1%"${d1##*[![:space:]]}"}"
    d2="${d2#"${d2%%[![:space:]]*}"}"; d2="${d2%"${d2##*[![:space:]]}"}"
    [[ -z "$d1" || -z "$d2" ]] && continue
    MAP_D1_TO_D2["$d1"]="$d2"
    MAP_D2_TO_D1["$d2"]="$d1"
  done < "$MAP_FILE"
  MAP_MTIME="$mtime"
  local count="${#MAP_D1_TO_D2[@]}"
  log_kv INFO event "MAP_RELOADED" file "$MAP_FILE" mtime "$mtime" pairs "$count"
}

to_dom1_fs(){ local u="$1"; [[ "$u" == *".dmz" ]] && { echo "$u"; return; }; [[ "$u" == *".adm" ]] && { echo "${u%.adm}.dmz"; return; }; echo "${u}.dmz"; }
to_dom2_fs(){ local u="$1"; [[ "$u" == *".adm" ]] && { echo "$u"; return; }; [[ "$u" == *".dmz" ]] && { echo "${u%.dmz}.adm"; return; }; echo "${u}.adm"; }

ensure_mount() {
  local p="$1"
  if ! mountpoint -q "$p"; then
    log WARN "Montage absent: $p -> tentative mount"
    if ! mount "$p" >>"$LOG" 2>&1; then
      log ERROR "Échec du montage: $p"; return 1
    fi
  fi
  local dev opts df_line
  dev="$(findmnt -n -o SOURCE --target "$p" || true)"
  opts="$(findmnt -n -o OPTIONS --target "$p" || true)"
  df_line="$(df -hP "$p" | awk 'NR==2{print "size="$2,"used="$3,"avail="$4,"use_pct="$5}')"
  log_kv INFO path "$p" device "$dev" options "$opts" $df_line
  return 0
}

stable_push() {
  local src="$1" dst="$2" direction="$3"
  [[ -d "$src" ]] || { log DEBUG "Source inexistante: $src"; return 0; }
  mkdir -p "$dst" "$QUARANTINE_DIR"

  shopt -s nullglob
  local files=()
  for f in "$src"/*; do [[ -f "$f" ]] && files+=("$f"); done

  log INFO "Analyse stabilité" "src=$src" "dst=$dst" "candidats=${#files[@]}"

  local stable=()
  for f in "${files[@]}"; do
    local s1 s2 mt sha
    s1=$(stat -c%s "$f" 2>/dev/null || echo -1)
    mt=$(stat -c%y "$f" 2>/dev/null || echo "n/a")
    sleep 2
    s2=$(stat -c%s "$f" 2>/dev/null || echo -2)
    if [[ "$s1" -ge 0 && "$s1" -eq "$s2" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then sha="$(sha256sum -- "$f" | awk '{print $1}')"; else sha="sha256:n/a"; fi
      log_kv INFO file "$f" event "QUEUE" size "$s1" mtime "$mt" sha256 "$sha" dir "$direction"
      stable+=("$f")
    else
      log_kv WARN file "$f" event "SKIP_UNSTABLE" size1 "$s1" size2 "$s2" mtime "$mt" dir "$direction"
    fi
  done

  [[ ${#stable[@]} -gt 0 ]] || { log INFO "Aucun fichier stable à transférer (src=$src)"; return 0; }

  local ok=0 fail=0 infected=0
  local clam_version; clam_version="$($CLAMSCAN_BIN -V 2>/dev/null || echo "clamscan n/a")"
  local dirdisp="${direction//->/_to_}"

  for f in "${stable[@]}"; do
    local base report_tmp report_name verdict sig scan_rc scan_out fsize
    base="$(basename "$f")"
    report_name="${base}${REPORT_SUFFIX}"
    fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)

    if [[ -x "$CLAMSCAN_BIN" ]]; then
      if scan_out="$("$CLAMSCAN_BIN" --no-summary --stdout -- "$f" 2>&1)"; then scan_rc=0; else scan_rc=$?; fi
      if   (( scan_rc == 0 )); then verdict="CLEAN";   sig=""
      elif (( scan_rc == 1 )); then verdict="INFECTED"; sig="$(awk -F': ' '/ FOUND$/{sub(/ FOUND$/,"",$2);print $2}' <<<"$scan_out" | head -1)"; ((infected++))
      else                        verdict="ERROR";    sig="Scan error"; ((infected++))
      fi
    else
      verdict="UNKNOWN"; sig="clamscan missing"; ((infected++)); log ERROR "clamscan introuvable — fichier BLOQUÉ"
    fi

    report_tmp="$(mktemp)"
    {
      echo "=== FTBridge / Rapport ClamAV ==="
      printf "Date           : %s\n" "$(date -u '+%F %T UTC')"
      printf "Moteur         : %s\n" "$clam_version"
      printf "Direction      : %s\n" "$direction"
      printf "Fichier        : %s\n" "$base"
      printf "Taille (octets): %s\n" "$fsize"
      printf "Source         : %s\n" "$f"
      printf "Destination    : %s\n" "$dst/"
      printf "Verdict        : %s\n" "$verdict"
      [[ -n "$sig" ]] && printf "Détails        : %s\n" "$sig"
      echo
      if [[ "$verdict" == "CLEAN" ]]; then
        echo "Le fichier a été transféré : aucun contenu malveillant détecté."
      elif [[ "$verdict" == "INFECTED" ]]; then
        echo "Le fichier a été BLOQUÉ et mis en quarantaine (non transféré)."
      else
        echo "Le fichier a été BLOQUÉ (erreur de scan) par sécurité."
      fi
      echo "================================="
    } >"$report_tmp"

    if [[ "$verdict" == "CLEAN" ]]; then
      if rsync -t --partial --partial-dir="$RSYNC_PARTIAL_DIR" --remove-source-files \
               --info=ALL2,FLIST2,PROGRESS2 --itemize-changes --human-readable \
               -- "$f" "$dst/" >>"$LOG" 2>&1; then
        log_kv INFO event "XFER" dir "$direction" path "$f" to "$dst/" size "$fsize"; ((ok++))
      else
        log_kv ERROR event "XFER_FAIL" dir "$direction" path "$f"; ((fail++))
      fi
      rsync -t --info=NAME -- "$report_tmp" "$dst/$report_name" >>"$LOG" 2>&1 || true
      rm -f -- "$report_tmp" || true
    else
      local qdir="$QUARANTINE_DIR/$(date +%F)/$dirdisp"; mkdir -p "$qdir"
      local qpath="$qdir/$base"
      if mv -f -- "$f" "$qpath"; then
        log_kv WARN event "QUARANTINE" dir "$direction" src "$f" qpath "$qpath" verdict "$verdict" details "$sig"
      else
        log_kv ERROR event "QUARANTINE_FAIL" dir "$direction" src "$f" verdict "$verdict"
      fi
      rsync -t --info=NAME -- "$report_tmp" "$dst/$report_name" >>"$LOG" 2>&1 || true
      rm -f -- "$report_tmp" || true
    fi
  done

  log_kv INFO event "RSYNC_SUMMARY" dir "$direction" ok "$ok" infected_blocked "$infected" failed "$fail"
  find "$src" -mindepth 1 -type d -empty -delete 2>/dev/null || true
}

main() {
  exec 9>"$LOCK" || exit 0
  if ! flock -n 9; then log WARN "Exécution déjà en cours, abandon du cycle."; exit 0; fi

  local start_ts end_ts; start_ts=$(date +%s)
  log INFO "=== CYCLE DEBUT ==="
  log_kv INFO kernel "$(uname -r)" hostname "$(hostname -f 2>/dev/null || hostname)" user "$(id -un)" pid "$$" sh "$(bash --version | head -1)"

  ensure_mount "$DOM1" || exit 0
  ensure_mount "$DOM2" || exit 0
  load_map

  # DOM1 -> DOM2
  while IFS= read -r -d '' uroot; do
    u="$(basename "$uroot")"
    usans="${u%%.dmz}"; usans="${usans%%.adm}"
    v="${MAP_D1_TO_D2[$usans]:-}"
    if [[ -z "$v" ]]; then
      log_kv WARN event "NO_MAPPING" dir "DOM1->DOM2" user_src "$u" hint "ajoutez une ligne à $MAP_FILE"
      continue
    fi
    vfs="$(to_dom2_fs "$v")"
    src="$uroot/IN"; dst="$DOM2/$vfs/OUT"; mkdir -p "$dst"
    log_kv INFO event "FLOW" dir "DOM1->DOM2" user_src "$u" user_dst "$v" from "$src" to "$dst"
    stable_push "$src" "$dst" "DOM1->DOM2" || true
  done < <(find "$DOM1" -mindepth 1 -maxdepth 1 -type d -print0)

  # DOM2 -> DOM1
  while IFS= read -r -d '' vroot; do
    v="$(basename "$vroot")"
    vsans="${v%%.adm}"; vsans="${vsans%%.dmz}"
    u="${MAP_D2_TO_D1[$vsans]:-}"
    if [[ -z "$u" ]]; then
      log_kv WARN event "NO_MAPPING" dir "DOM2->DOM1" user_src "$v" hint "ajoutez une ligne à $MAP_FILE"
      continue
    fi
    ufs="$(to_dom1_fs "$u")"
    src="$vroot/IN"; dst="$DOM1/$ufs/OUT"; mkdir -p "$dst"
    log_kv INFO event "FLOW" dir "DOM2->DOM1" user_src "$v" user_dst "$u" from "$src" to "$dst"
    stable_push "$src" "$dst" "DOM2->DOM1" || true
  done < <(find "$DOM2" -mindepth 1 -maxdepth 1 -type d -print0)

  end_ts=$(date +%s); local dur=$(( end_ts - start_ts ))
  log_kv INFO event "CYCLE_END" duration_s "$dur"
  log INFO "=== CYCLE FIN (${dur}s) ==="
}
main
EOF
  chmod +x /usr/local/sbin/ftbridge_sync.sh
  : > "$LOGFILE"
}

install_add_mapping() {
  # Version cohérente avec le format à 4 colonnes + en-tête
  cat >/usr/local/sbin/add_mapping <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
exec /usr/bin/env bash -c '
MAP="/etc/ftbridge/map.csv"
d1=""; d2=""; d1d=""; d2d=""; FORCE=0

usage(){ cat <<USAGE
Usage:
  add_mapping --dom1-user <u1> --dom2-user <u2> [--dom1-dir <d1>] [--dom2-dir <d2>] [--force]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dom1-user) d1="$2"; shift 2;;
    --dom2-user) d2="$2"; shift 2;;
    --dom1-dir)  d1d="$2"; shift 2;;
    --dom2-dir)  d2d="$2"; shift 2;;
    --force)     FORCE=1; shift;;
    -h|--help)   usage; exit 0;;
    *) echo "Argument inconnu: $1"; usage; exit 1;;
  esac
done

[[ -n "$d1" && -n "$d2" ]] || { usage; exit 1; }

strip(){ sed -E "s/\.(dmz|adm)$//I"; }
d1="$(printf "%s" "$d1" | xargs | strip)"
d2="$(printf "%s" "$d2" | xargs | strip)"
[[ -n "$d1d" ]] || d1d="$d1"
[[ -n "$d2d" ]] || d2d="$d2"

mkdir -p "$(dirname "$MAP")"
touch "$MAP"; chmod 640 "$MAP"

exec 9<>"$MAP"; flock 9

if [[ ! -s "$MAP" || "$(head -n1 "$MAP")" != "dom1_user,dom2_user,dom1_dir,dom2_dir" ]]; then
  tmp="$(mktemp)"
  { echo "dom1_user,dom2_user,dom1_dir,dom2_dir"; awk "NR>1 && \$0!~/^\\s*(#|$)/{print}" "$MAP" 2>/dev/null || true; } >"$tmp"
  cat "$tmp" >"$MAP"; rm -f "$tmp"
fi

existing="$(awk -F, -v u1="$d1" -v u2="$d2" "BEGIN{IGNORECASE=1} NR>1 && tolower(\$1)==tolower(u1) && tolower(\$2)==tolower(u2){print; exit}" "$MAP" || true)"

if [[ -n "$existing" ]]; then
  IFS=, read -r e1 e2 e3 e4 <<<"$existing"
  if [[ "$e3" == "$d1d" && "$e4" == "$d2d" ]]; then
    echo "Mapping déjà présent: $existing"; exit 0
  else
    if (( FORCE )); then
      tmp="$(mktemp)"
      awk -F, -v OFS=, -v u1="$d1" -v u2="$d2" -v nd1="$d1d" -v nd2="$d2d" "BEGIN{IGNORECASE=1} NR==1{print; next} (tolower(\$1)==tolower(u1)&&tolower(\$2)==tolower(u2)){print \$1,\$2,nd1,nd2; next} {print}" "$MAP" >"$tmp"
      cat "$tmp" >"$MAP"; rm -f "$tmp"
      echo "Mapping mis à jour: $d1,$d2,$d1d,$d2d"; exit 0
    else
      echo "Différent: existant=$existing, nouveau=$d1,$d2,$d1d,$d2d (utilisez --force)"; exit 2
    fi
  fi
else
  echo "$d1,$d2,$d1d,$d2d" >>"$MAP"
  echo "OK: ajouté $d1,$d2,$d1d,$d2d -> $MAP"
fi
'
EOF
  chmod +x /usr/local/sbin/add_mapping

  # Fichier map si absent (avec en-tête)
  if [[ ! -f "$MAP_FILE" ]]; then
    mkdir -p "$MAP_DIR"
    cat >"$MAP_FILE" <<'EOF'
dom1_user,dom2_user,dom1_dir,dom2_dir
# Exemple:
# j.doe-admin,john.doe,j.doe-admin,john.doe
EOF
    chmod 640 "$MAP_FILE"
  fi
}

install_logrotate() {
  say "=== 4b) logrotate pour $LOGFILE ==="
  cat >/etc/logrotate.d/ftbridge <<EOF
$LOGFILE {
  daily
  rotate 14
  size 10M
  compress
  missingok
  notifempty
  create 0640 root root
  sharedscripts
}
EOF
}

install_systemd_timer() {
  say "=== 5) Service + Timer systemd (10s) ==="

  cat >/etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=FTBridge sync bi-directionnelle (IN->OUT) DOM1<->DOM2 (+ ClamAV + mapping)
After=network-online.target remote-fs.target
Wants=network-online.target
RequiresMountsFor=$MNT1 $MNT2

[Service]
Type=oneshot
Environment=LOG_LEVEL=INFO
ExecStart=/usr/local/sbin/ftbridge_sync.sh
Nice=10
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ftbridge-sync

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

  systemctl daemon-reload
  systemctl enable --now $TIMER_NAME
}

# ==================== Exécution ====================
need_root
pick_ifaces
config_ips
install_pkgs
collect_creds
setup_fstab_and_mounts
install_ftbridge_sync
install_add_mapping
install_logrotate
install_systemd_timer

say "=== OK ===
- Mapping : $MAP_FILE (à remplir via add_mapping)
- Script  : /usr/local/sbin/ftbridge_sync.sh
- Montages: $MNT1 et $MNT2 (SMB 3.1.1 + seal, noexec/nosuid/nodev)
- Logs    : $LOGFILE (rotation quotidienne + taille)
- Service : $SERVICE_NAME + $TIMER_NAME (~10s)
- Pare-feu: nftables actif, FORWARD=DROP
"
