#!/usr/bin/env bash
set -Eeuo pipefail

# ================== Paramètres réseau / domaines ==================
IP_DOM1="192.168.10.1/24"
IP_DOM2="10.10.240.1/24"

DOM1_DC_IP="192.168.10.2"
DOM2_DC_IP="10.10.240.2"
SHARE="Transactions"

DOM1_USER="svc_relay_dom1"
DOM2_USER="svc_relay_dom2"
DOM1_DOMAIN="DOM1"
DOM2_DOMAIN="DOM2"

# ================== Chemins & fichiers ==================
MNT1="/mnt/dom1_transactions"
MNT2="/mnt/dom2_transactions"
LOGDIR="/var/log/ftbridge"
LOGFILE="$LOGDIR/sync.log"

CONF_DIR="/etc/ftbridge"
MAP_FILE="$CONF_DIR/map.csv"

SERVICE_NAME="ftbridge-sync.service"
TIMER_NAME="ftbridge-sync.timer"
SYNC_BIN="/usr/local/sbin/ftbridge_sync.sh"

# ================== Utils ==================
say(){ echo -e "$*"; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; }

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
}

install_pkgs() {
  say "=== 2) Paquets ==="
  apt-get update -y || true
  apt-get install -y --no-install-recommends \
    cifs-utils rsync smbclient coreutils util-linux psmisc \
    clamav clamav-freshclam clamav-daemon nftables

  mkdir -p "$MNT1" "$MNT2" "$LOGDIR" /var/quarantine/ftbridge "$CONF_DIR"
  chmod 700 /var/quarantine/ftbridge
  umask 077

  # Mapping CSV initial
  if [[ ! -f "$MAP_FILE" ]]; then
    cat >"$MAP_FILE" <<'EOF'
# Fichier de mapping FTBridge (CSV, séparateur virgule)
# Lignes vides et lignes commençant par # sont ignorées.
# En-tête (obligatoire) :
# dom1_user,dom2_user,dom1_dir,dom2_dir
#
# Règles :
# - dom1_user/dom2_user : identifiants utilisateur dans chaque domaine (SAM ou nom logique côté partage).
# - dom1_dir/dom2_dir   : nom de dossier dans le partage "Transactions" de chaque domaine.
#   Si vide, on prend par défaut domX_user.
# - Au moins un couple d'identité doit être présent pour que la ligne soit utile.
#
# Exemples :
#  j.doe-admin,john.doe,,          # Dossiers = j.doe-admin (DOM1) et john.doe (DOM2)
#  app.bot,svc.app,app.bot,svc.app # Dossiers explicitement nommés
#  jean.dupont,jean.dupont,,       # Identiques dans les deux domaines
dom1_user,dom2_user,dom1_dir,dom2_dir
j.doe-admin,john.doe,,
EOF
    chmod 640 "$MAP_FILE"
  fi

  # ClamAV (signatures + daemon)
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  freshclam --stdout || true
  systemctl enable --now clamav-freshclam >/dev/null 2>&1 || true
  systemctl enable --now clamav-daemon >/dev/null 2>&1 || true
}

install_firewall() {
  say "=== 2b) Pare-feu (nftables) : DROP du forward ==="
  cat >/etc/nftables.conf <<'EOF'
flush ruleset
table inet filter {
  chain input { type filter hook input priority 0; policy accept; }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
  systemctl enable --now nftables
}

write_creds() {
  # Permet aussi DOM1_PASS / DOM2_PASS via variables d'env (CI/CD)
  install -m 600 /dev/null /root/.cred_dom1
  if [[ -z "${DOM1_PASS:-}" ]]; then
    read -rsp "Mot de passe $DOM1_DOMAIN\\$DOM1_USER : " DOM1_PASS; echo
  fi
  cat >/root/.cred_dom1 <<EOF
username=$DOM1_USER
password=$DOM1_PASS
domain=$DOM1_DOMAIN
EOF

  install -m 600 /dev/null /root/.cred_dom2
  if [[ -z "${DOM2_PASS:-}" ]]; then
    read -rsp "Mot de passe $DOM2_DOMAIN\\$DOM2_USER : " DOM2_PASS; echo
  fi
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
//$DOM1_DC_IP/$SHARE $MNT1 cifs credentials=/root/.cred_dom1,vers=3.1.1,sec=ntlmssp,seal,uid=0,gid=0,file_mode=0640,dir_mode=0750,soft,noperm,noexec,nosuid,nodev 0 0
//$DOM2_DC_IP/$SHARE $MNT2 cifs credentials=/root/.cred_dom2,vers=3.1.1,sec=ntlmssp,seal,uid=0,gid=0,file_mode=0640,dir_mode=0750,soft,noperm,noexec,nosuid,nodev 0 0
EOF

  systemctl daemon-reload || true
  mount -a || true
  echo "Montages actifs :"
  mount | grep -E "$MNT1|$MNT2" || echo "  (pas encore monté)"
}

install_sync_script() {
  say "=== 4) Script de synchronisation (écriture complète) ==="
  cat >"$SYNC_BIN" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

# ------------ Configuration ------------
LOG="/var/log/ftbridge/sync.log"
DOM1="/mnt/dom1_transactions"
DOM2="/mnt/dom2_transactions"
LOCK="/run/ftbridge.sync.lock"
LOG_LEVEL="${LOG_LEVEL:-DEBUG}"   # DEBUG|INFO|WARN|ERROR
RSYNC_PARTIAL_DIR=".rsync-partial"

# Fichier de mapping (CSV)
CONF_DIR="${CONF_DIR:-/etc/ftbridge}"
MAP_FILE="${MAP_FILE:-$CONF_DIR/map.csv}"

# ClamAV : privilégie clamdscan si dispo (perf), sinon clamscan
if command -v clamdscan >/dev/null 2>&1; then
  CLAMSCAN_BIN="${CLAMSCAN_BIN:-/usr/bin/clamdscan}"
else
  CLAMSCAN_BIN="${CLAMSCAN_BIN:-/usr/bin/clamscan}"
fi
QUARANTINE_DIR="${QUARANTINE_DIR:-/var/quarantine/ftbridge}"
REPORT_SUFFIX="_clamav"

# ------------ Utilitaires de log ------------
_lvl_num(){ case "${1^^}" in DEBUG) echo 10;; INFO) echo 20;; WARN) echo 30;; ERROR) echo 40;; *) echo 20;; esac; }
_should_log(){ [[ $(_lvl_num "$1") -ge $(_lvl_num "$LOG_LEVEL") ]]; }
log(){ local lvl="${1:-INFO}"; shift || true; _should_log "$lvl" || return 0; printf "[%(%F %T)T] %-5s pid=%s %s\n" -1 "${lvl^^}" "$$" "$*" >>"$LOG"; }
log_kv(){ local lvl="${1:-INFO}"; shift; _should_log "$lvl" || return 0; printf "[%(%F %T)T] %-5s pid=%s " -1 "${lvl^^}" "$$" >>"$LOG"; printf "%s=%q " "$@" >>"$LOG"; printf "\n" >>"$LOG"; }

# ------------ Mapping CSV : chargement & résolution ------------
# Format attendu (en-tête obligatoire) :
# dom1_user,dom2_user,dom1_dir,dom2_dir
#
# - domX_user : identifiant côté domaine (ex. "j.doe-admin" / "john.doe")
# - domX_dir  : nom du dossier dans le partage Transactions (si vide => domX_user)
#
# On construit 4 tables :
#  - D1U->D2U, D2U->D1U  (utilisateurs)
#  - D1D->D2D, D2D->D1D  (dossiers)
#
# Rechargé automatiquement si MAP_FILE est modifié (mtime).

declare -A MAP_D1U_TO_D2U MAP_D2U_TO_D1U MAP_D1D_TO_D2D MAP_D2D_TO_D1D
MAP_MTIME=0

_trim_csv_field(){ local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

load_mapping() {
  [[ -f "$MAP_FILE" ]] || { log WARN "Mapping absent: $MAP_FILE"; return 0; }
  local mtime
  mtime="$(stat -c %Y "$MAP_FILE" 2>/dev/null || echo 0)"
  if [[ "$mtime" -eq "$MAP_MTIME" ]]; then
    return 0
  fi

  MAP_D1U_TO_D2U=(); MAP_D2U_TO_D1U=(); MAP_D1D_TO_D2D=(); MAP_D2D_TO_D1D=()

  local line n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((n++))
    [[ -z "${line// }" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue

    IFS=',' read -r f1 f2 f3 f4 <<<"$line"
    if (( n == 1 )); then
      local h1 h2 h3 h4
      h1="$(_trim_csv_field "$f1" | tr '[:upper:]' '[:lower:]')"
      h2="$(_trim_csv_field "$f2" | tr '[:upper:]' '[:lower:]')"
      h3="$(_trim_csv_field "$f3" | tr '[:upper:]' '[:lower:]')"
      h4="$(_trim_csv_field "$f4" | tr '[:upper:]' '[:lower:]')"
      if [[ "$h1,$h2,$h3,$h4" != "dom1_user,dom2_user,dom1_dir,dom2_dir" ]]; then
        log ERROR "Entête CSV invalide dans $MAP_FILE (ligne 1)"
        break
      fi
      continue
    fi

    local d1u d2u d1d d2d
    d1u="$(_trim_csv_field "$f1")"
    d2u="$(_trim_csv_field "$f2")"
    d1d="$(_trim_csv_field "$f3")"
    d2d="$(_trim_csv_field "$f4")"

    [[ -z "$d1d" && -n "$d1u" ]] && d1d="$d1u"
    [[ -z "$d2d" && -n "$d2u" ]] && d2d="$d2u"
    [[ -z "$d1u$d2u$d1d$d2d" ]] && continue

    if [[ -n "$d1u" && -n "$d2u" ]]; then
      MAP_D1U_TO_D2U["$d1u"]="$d2u"
      MAP_D2U_TO_D1U["$d2u"]="$d1u"
    fi
    if [[ -n "$d1d" && -n "$d2d" ]]; then
      MAP_D1D_TO_D2D["$d1d"]="$d2d"
      MAP_D2D_TO_D1D["$d2d"]="$d1d"
    fi
  done <"$MAP_FILE"

  MAP_MTIME="$mtime"
  log_kv INFO event "MAP_RELOADED" file "$MAP_FILE" mtime "$MAP_MTIME"
}

# Fallback historique : substitution .dmz <-> .adm et *_in <-> *_out
map_suffix_to_dom2(){
  local u="$1"
  if [[ "$u" == *".dmz" ]]; then echo "${u%.dmz}.adm"; return; fi
  if [[ "$u" == *"_in"  ]]; then echo "${u%_in}_out"; return; fi
  echo "$u"
}
map_suffix_to_dom1(){
  local u="$1"
  if [[ "$u" == *".adm" ]]; then echo "${u%.adm}.dmz"; return; fi
  if [[ "$u" == *"_out" ]]; then echo "${u%_out}_in"; return; fi
  echo "$u"
}

resolve_from_dom1(){
  local user1="$1" dir1="$2"
  local user2 dir2
  load_mapping
  if [[ -n "${MAP_D1U_TO_D2U[$user1]:-}" ]]; then
    user2="${MAP_D1U_TO_D2U[$user1]}"
  else
    user2="$(map_suffix_to_dom2 "$user1")"
  fi
  if [[ -n "${MAP_D1D_TO_D2D[$dir1]:-}" ]]; then
    dir2="${MAP_D1D_TO_D2D[$dir1]}"
  else
    dir2="$user2"
  fi
  printf '%s;%s\n' "$user2" "$dir2"
}

resolve_from_dom2(){
  local user2="$1" dir2="$2"
  local user1 dir1
  load_mapping
  if [[ -n "${MAP_D2U_TO_D1U[$user2]:-}" ]]; then
    user1="${MAP_D2U_TO_D1U[$user2]}"
  else
    user1="$(map_suffix_to_dom1 "$user2")"
  fi
  if [[ -n "${MAP_D2D_TO_D1D[$dir2]:-}" ]]; then
    dir1="${MAP_D2D_TO_D1D[$dir2]}"
  else
    dir1="$user1"
  fi
  printf '%s;%s\n' "$user1" "$dir1"
}

# ------------ Vérifs montages & infos FS ------------
ensure_mount() {
  local p="$1"
  if ! mountpoint -q "$p"; then
    log WARN "Montage absent: $p -> tentative mount"
    if ! mount "$p" >>"$LOG" 2>&1; then
      log ERROR "Échec du montage: $p"
      return 1
    fi
  fi
  local dev opts
  dev="$(findmnt -n -o SOURCE --target "$p" || true)"
  opts="$(findmnt -n -o OPTIONS --target "$p" || true)"
  local df_line
  df_line="$(df -hP "$p" | awk 'NR==2{print "size="$2,"used="$3,"avail="$4,"use%="$5}')"
  log_kv INFO path "$p" device "$dev" options "$opts" $df_line
  return 0
}

# ------------ Détection de stabilité + transfert + ClamAV ------------
stable_push() {
  local src="$1" dst="$2" direction="$3"
  [[ -d "$src" ]] || { log DEBUG "Source inexistante: $src"; return 0; }
  mkdir -p "$dst" "$QUARANTINE_DIR"

  shopt -s nullglob
  local files=()
  for f in "$src"/*; do
    [[ -f "$f" ]] && files+=("$f")
  done

  log INFO "Analyse stabilité" "src=$src" "dst=$dst" "candidats=${#files[@]}"

  local stable=()
  declare -A SHA_CACHE=()

  for f in "${files[@]}"; do
    local size1 size2 mtime sha
    size1=$(stat -c%s "$f" 2>/dev/null || echo -1)
    mtime=$(stat -c%y "$f" 2>/dev/null || echo "n/a")
    sleep 2
    size2=$(stat -c%s "$f" 2>/dev/null || echo -2)
    if [[ "$size1" -ge 0 && "$size1" -eq "$size2" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        sha="$(sha256sum -- "$f" | awk '{print $1}')"
      else
        sha="sha256:n/a"
      fi
      SHA_CACHE["$f"]="$sha"
      log_kv INFO file "$f" event "QUEUE" size "$size1" mtime "$mtime" sha256 "$sha" dir "$direction"
      stable+=("$f")
    else
      log_kv WARN file "$f" event "SKIP_UNSTABLE" size1 "$size1" size2 "$size2" mtime "$mtime" dir "$direction"
    fi
  done

  [[ ${#stable[@]} -gt 0 ]] || { log INFO "Aucun fichier stable à transférer (src=$src)"; return 0; }

  local ok=0 fail=0 infected=0
  local clam_version
  clam_version="$($CLAMSCAN_BIN -V 2>/dev/null || echo "clamscan n/a")"

  local dirdisp="${direction//->/_to_}"

  for f in "${stable[@]}"; do
    local fsize base report_tmp report_name verdict sig scan_rc scan_out sha
    base="$(basename "$f")"
    report_name="${base}${REPORT_SUFFIX}"
    fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
    sha="${SHA_CACHE["$f"]:-n/a}"

    # --- Scan ClamAV ---
    if [[ -x "$CLAMSCAN_BIN" ]]; then
      if scan_out="$("$CLAMSCAN_BIN" --no-summary --stdout -- "$f" 2>&1)"; then
        scan_rc=0
      else
        scan_rc=$?
      fi
      if (( scan_rc == 0 )); then
        verdict="CLEAN"; sig=""
      elif (( scan_rc == 1 )); then
        verdict="INFECTED"
        sig="$(awk -F': ' '/ FOUND$/{sub(/ FOUND$/,"",$2);print $2}' <<<"$scan_out" | head -1)"
        ((infected++))
      else
        verdict="ERROR"; sig="Scan error"; ((infected++))
      fi
    else
      verdict="UNKNOWN"; sig="clamscan missing"; ((infected++))
      log ERROR "clamscan/clamdscan introuvable — fichier BLOQUÉ"
    fi

    # --- Rapport user-friendly ---
    report_tmp="$(mktemp)"
    {
      echo "=== FTBridge / Rapport ClamAV ==="
      printf "Date           : %s\n" "$(date -u '+%F %T UTC')"
      printf "Moteur         : %s\n" "$clam_version"
      printf "Direction      : %s\n" "$direction"
      printf "Fichier        : %s\n" "$base"
      printf "Taille (octets): %s\n" "$fsize"
      printf "SHA256         : %s\n" "$sha"
      printf "Source         : %s\n" "$f"
      printf "Destination    : %s\n" "$dst/"
      printf "Verdict        : %s\n" "$verdict"
      [[ -n "$sig" ]] && printf "Détails        : %s\n" "$sig"
      echo
      if [[ "$verdict" == "CLEAN" ]]; then
        echo "Le fichier a été transféré car aucun contenu malveillant n’a été détecté."
      elif [[ "$verdict" == "INFECTED" ]]; then
        echo "Le fichier a été BLOQUÉ et placé en quarantaine (non transféré) car il contient un élément malveillant."
      else
        echo "Le fichier a été BLOQUÉ (erreur de scan) par mesure de sécurité."
      fi
      echo "================================="
    } >"$report_tmp"

    # --- Action selon verdict ---
    if [[ "$verdict" == "CLEAN" ]]; then
      if rsync -t --partial --partial-dir="$RSYNC_PARTIAL_DIR" --remove-source-files \
               --info=ALL2,FLIST2,PROGRESS2 --itemize-changes --human-readable \
               -- "$f" "$dst/" >>"$LOG" 2>&1; then
        log_kv INFO event "XFER" dir "$direction" path "$f" to "$dst/" size "$fsize"
        ((ok++))
      else
        log_kv ERROR event "XFER_FAIL" dir "$direction" path "$f"
        ((fail++))
      fi
      rsync -t --info=NAME -- "$report_tmp" "$dst/$report_name" >>"$LOG" 2>&1 || true
      rm -f -- "$report_tmp" || true
    else
      local qdir="$QUARANTINE_DIR/$(date +%F)/$dirdisp"
      mkdir -p "$qdir"
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

  # Nettoyage
  find "$src" -mindepth 1 -type d -name "$RSYNC_PARTIAL_DIR" -empty -delete 2>/dev/null || true
  find "$src" -mindepth 1 -type d -empty -delete 2>/dev/null || true

  return 0
}

# ------------ Boucle principale ------------
main() {
  exec 9>"$LOCK" || exit 0
  if ! flock -n 9; then
    log WARN "Exécution déjà en cours, abandon du cycle."
    exit 0
  fi

  local start_ts end_ts
  start_ts=$(date +%s)

  log INFO "=== CYCLE DEBUT ==="
  log_kv INFO kernel "$(uname -r)" hostname "$(hostname -f 2>/dev/null || hostname)" \
                 user "$(id -un)" pid "$$" sh "$(bash --version | head -1)"

  ensure_mount "$DOM1" || exit 0
  ensure_mount "$DOM2" || exit 0

  # DOM1 -> DOM2 (IN -> OUT)
  while IFS= read -r -d '' uroot; do
    local u dir_from u2 dir_to_name dst
    u="$(basename "$uroot")"
    dir_from="$uroot/IN"
    [[ -d "$dir_from" ]] || { log_kv DEBUG event "NO_IN" user "$u" base "$uroot"; continue; }
    IFS=';' read -r u2 dir_to_name < <(resolve_from_dom1 "$u" "$u")
    dst="$DOM2/$dir_to_name/OUT"
    log_kv INFO event "FLOW" dir "DOM1->DOM2" user_src "$u" user_dst "$u2" from "$dir_from" to "$dst"
    mkdir -p "$dst"
    stable_push "$dir_from" "$dst" "DOM1->DOM2" || true
  done < <(find "$DOM1" -mindepth 1 -maxdepth 1 -type d -print0)

  # DOM2 -> DOM1 (IN -> OUT)
  while IFS= read -r -d '' vroot; do
    local v dir_from v2 dir_to_name dst
    v="$(basename "$vroot")"
    dir_from="$vroot/IN"
    [[ -d "$dir_from" ]] || { log_kv DEBUG event "NO_IN" user "$v" base "$vroot"; continue; }
    IFS=';' read -r v2 dir_to_name < <(resolve_from_dom2 "$v" "$v")
    dst="$DOM1/$dir_to_name/OUT"
    log_kv INFO event "FLOW" dir "DOM2->DOM1" user_src "$v" user_dst "$v2" from "$dir_from" to "$dst"
    mkdir -p "$dst"
    stable_push "$dir_from" "$dst" "DOM2->DOM1" || true
  done < <(find "$DOM2" -mindepth 1 -maxdepth 1 -type d -print0)

  end_ts=$(date +%s)
  local dur=$(( end_ts - start_ts ))
  log_kv INFO event "CYCLE_END" duration_s "$dur"
  log INFO "=== CYCLE FIN (${dur}s) ==="
}

main
EOF
  chmod +x "$SYNC_BIN"
  : > "$LOGFILE"
}

install_logrotate() {
  say "=== 4b) logrotate pour $LOGFILE ==="
  cat >/etc/logrotate.d/ftbridge <<EOF
$LOGFILE {
  daily
  rotate 14
  compress
  missingok
  notifempty
  size 50M
  create 0640 root root
  sharedscripts
  postrotate
    :
  endscript
}
EOF
}

install_systemd_timer() {
  say "=== 5) Service + Timer systemd (10s) ==="

  cat >/etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=FTBridge sync bi-directionnelle (IN->OUT) DOM1<->DOM2 (+ ClamAV + quarantaine + mapping)
After=network-online.target remote-fs.target
Wants=network-online.target
RequiresMountsFor=$MNT1 $MNT2

[Service]
Type=oneshot
Environment=LOG_LEVEL=DEBUG
Environment=MAP_FILE=$MAP_FILE
Environment=CONF_DIR=$CONF_DIR
ExecStart=$SYNC_BIN
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

# ================== Exécution ==================
need_root
pick_ifaces
config_ips
install_pkgs
install_firewall
write_creds
setup_fstab_and_mounts
install_sync_script
install_logrotate
install_systemd_timer

say "=== OK ===
- Mapping : $MAP_FILE (rechargé automatiquement à chaque changement)
- Script  : $SYNC_BIN
- Montages: $MNT1 et $MNT2 (SMB 3.1.1 + seal, noexec/nosuid/nodev)
- Logs    : $LOGFILE (rotation quotidienne + taille)
- Service : $SERVICE_NAME + $TIMER_NAME (~10s)
- Pare-feu: nftables actif, FORWARD=DROP
"
