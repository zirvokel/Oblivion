#!/usr/bin/env bash
set -Eeuo pipefail

CONF_DIR="/etc/ftbridge"
MAP_FILE="$CONF_DIR/map.csv"

usage(){
  cat <<'EOF'
Usage:
  add_mapping --dom1-user <u1> --dom2-user <u2> [--dom1-dir <d1>] [--dom2-dir <d2>] [--force]

Ajoute/actualise une ligne dans /etc/ftbridge/map.csv :
  dom1_user,dom2_user,dom1_dir,dom2_dir

- dom1_user / dom2_user : SAM "logiques" (sans suffixe .dmz/.adm)
- dom1_dir  / dom2_dir  : noms de dossiers (par défaut = dom1_user/dom2_user)
  (La passerelle ajoute les suffixes réels sur le FS au moment du transfert)

--force : met à jour la ligne si elle existe et diffère.
EOF
}

# --------- Parsing arguments ----------
D1U="" D2U="" D1D="" D2D="" FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dom1-user) D1U="${2:-}"; shift 2;;
    --dom2-user) D2U="${2:-}"; shift 2;;
    --dom1-dir)  D1D="${2:-}"; shift 2;;
    --dom2-dir)  D2D="${2:-}"; shift 2;;
    --force)     FORCE=1; shift;;
    -h|--help)   usage; exit 0;;
    *) echo "Option inconnue: $1"; usage; exit 1;;
  esac
done

# --------- Vérifs & normalisation ----------
[[ -n "${D1U}" && -n "${D2U}" ]] || { echo "Erreur: --dom1-user et --dom2-user sont requis."; usage; exit 1; }

# Exiger root plutôt que 'sudo -n true' (peut ne pas exister)
[[ $EUID -eq 0 ]] || { echo "Ce script nécessite root."; exit 1; }

# Supprime suffixes éventuels (.dmz/.adm) sur les identités logiques
strip_suf(){ sed -E 's/\.(dmz|adm)$//I'; }
D1U="$(printf '%s' "$D1U" | tr -d '\r' | xargs | strip_suf)"
D2U="$(printf '%s' "$D2U" | tr -d '\r' | xargs | strip_suf)"

# Par défaut, les répertoires logiques suivent les identités logiques (sans suffixe)
[[ -n "${D1D}" ]] || D1D="$D1U"
[[ -n "${D2D}" ]] || D2D="$D2U"

# Interdit les virgules (CSV)
for v in "$D1U" "$D2U" "$D1D" "$D2D"; do
  [[ "$v" != *","* ]] || { echo "Erreur: les valeurs ne doivent pas contenir de virgule: '$v'"; exit 1; }
done

# --------- Prépare le fichier + lock global ----------
mkdir -p "$CONF_DIR"
touch "$MAP_FILE"
chmod 640 "$MAP_FILE"

exec 9<>"$MAP_FILE"
flock 9

# En-tête (si absent/incorrect, on le (ré)écrit en conservant le contenu)
if [[ ! -s "$MAP_FILE" || "$(head -n1 "$MAP_FILE" || true)" != "dom1_user,dom2_user,dom1_dir,dom2_dir" ]]; then
  tmp="$(mktemp)"
  {
    echo "dom1_user,dom2_user,dom1_dir,dom2_dir"
    awk 'NR>1 && $0!~/^\s*(#|$)/{print $0}' "$MAP_FILE" 2>/dev/null || true
  } >"$tmp"
  cat "$tmp" >"$MAP_FILE"; rm -f "$tmp"
fi

# Recherche case-insensitive sur les 2 premières colonnes (identités logiques)
existing="$(awk -F',' -v u1="$D1U" -v u2="$D2U" '
  BEGIN{IGNORECASE=1}
  NR>1 && tolower($1)==tolower(u1) && tolower($2)==tolower(u2) {print $0; exit}
' "$MAP_FILE" || true)"

if [[ -n "$existing" ]]; then
  IFS=',' read -r e1 e2 e3 e4 <<<"$existing"
  if [[ "$e3" == "$D1D" && "$e4" == "$D2D" ]]; then
    echo "Entrée déjà présente, inchangée:"
    echo "  $existing"
    exit 0
  else
    if (( FORCE )); then
      tmp="$(mktemp)"
      awk -F',' -v OFS=',' -v u1="$D1U" -v u2="$D2U" -v nd1="$D1D" -v nd2="$D2D" '
        BEGIN{IGNORECASE=1}
        NR==1 {print; next}
        (tolower($1)==tolower(u1) && tolower($2)==tolower(u2)) {print $1,$2,nd1,nd2; next}
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
