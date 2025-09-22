#!/usr/bin/env bash
set -Eeuo pipefail

CONF_DIR="/etc/ftbridge"
MAP_FILE="$CONF_DIR/map.csv"

usage(){
  cat <<EOF
Usage:
  $0 --dom1-user <u1> --dom2-user <u2> [--dom1-dir <d1>] [--dom2-dir <d2>] [--force]

Ajoute/actualise une ligne dans $MAP_FILE :
  dom1_user,dom2_user,dom1_dir,dom2_dir

Par défaut, dom1_dir=dom1_user et dom2_dir=dom2_user.
--force : met à jour une entrée existante si elle diffère.
EOF
}

# Parse args
D1U="" D2U="" D1D="" D2D="" FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dom1-user) D1U="$2"; shift 2;;
    --dom2-user) D2U="$2"; shift 2;;
    --dom1-dir)  D1D="$2"; shift 2;;
    --dom2-dir)  D2D="$2"; shift 2;;
    --force)     FORCE=1; shift;;
    -h|--help)   usage; exit 0;;
    *) echo "Option inconnue: $1"; usage; exit 1;;
  esac
done

[[ -n "$D1U" && -n "$D2U" ]] || { echo "dom1-user et dom2-user sont requis."; usage; exit 1; }
[[ -n "$D1D" ]] || D1D="$D1U"
[[ -n "$D2D" ]] || D2D="$D2U"

sudo -n true 2>/dev/null || { echo "Ce script nécessite sudo/root."; exit 1; }

mkdir -p "$CONF_DIR"
touch "$MAP_FILE"
chmod 640 "$MAP_FILE"

# Si fichier vide : écrire entête
if [[ ! -s "$MAP_FILE" || "$(head -n1 "$MAP_FILE")" != "dom1_user,dom2_user,dom1_dir,dom2_dir" ]]; then
  tmp="$(mktemp)"; echo "dom1_user,dom2_user,dom1_dir,dom2_dir" >"$tmp"
  # Concatène les lignes existantes non vides/non commentaires
  awk 'NR>1 && $0!~/^\s*(#|$)/{print $0}' "$MAP_FILE" >>"$tmp" || true
  cat "$tmp" >"$MAP_FILE"; rm -f "$tmp"
fi

# Section critique avec flock
exec 9<>"$MAP_FILE"
flock 9

# Cherche s'il existe déjà une entrée pour ce couple d'utilisateurs
existing="$(awk -F',' -v u1="$D1U" -v u2="$D2U" 'NR>1 && $1==u1 && $2==u2 {print $0}' "$MAP_FILE" || true)"

if [[ -n "$existing" ]]; then
  IFS=',' read -r e1 e2 e3 e4 <<<"$existing"
  if [[ "$e3" == "$D1D" && "$e4" == "$D2D" ]]; then
    echo "Entrée déjà présente, inchangée:"
    echo "  $existing"
    exit 0
  else
    if (( FORCE )); then
      # Réécrit le fichier en remplaçant la ligne
      tmp="$(mktemp)"
      awk -F',' -v OFS=',' -v u1="$D1U" -v u2="$D2U" -v nd1="$D1D" -v nd2="$D2D" '
        NR==1 {print; next}
        ($1==u1 && $2==u2) {print $1,$2,nd1,nd2; next}
        {print}
      ' "$MAP_FILE" >"$tmp"
      cat "$tmp" >"$MAP_FILE"; rm -f "$tmp"
      echo "Entrée mise à jour:"
      echo "  $D1U,$D2U,$D1D,$D2D"
      exit 0
    else
      echo "Entrée différente déjà existante. Utilisez --force pour mettre à jour."
      echo "  existant:  $existing"
      echo "  nouveau :  $D1U,$D2U,$D1D,$D2D"
      exit 2
    fi
  fi
else
  echo "$D1U,$D2U,$D1D,$D2D" >>"$MAP_FILE"
  echo "Entrée ajoutée:"
  echo "  $D1U,$D2U,$D1D,$D2D"
fi
