#!/usr/bin/env bash
# ufw-hardened.sh — hardened ufw profile for bug bounty work (outbound only)
# Repo: https://github.com/danboy-lab/dfw
#
# Usage:
#   sudo bash ufw-hardened.sh --all
#   sudo bash ufw-hardened.sh --verify
#   sudo bash ufw-hardened.sh --rollback
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
MARK_BEGIN="# BB-BLOCKLIST-BEGIN"
MARK_END="# BB-BLOCKLIST-END"
IPSET_SET="bb-blocklist"
BACKUP_ROOT="/tmp/bb-ufw-backup"

ASSUME_YES=0
DO_BASELINE=0
DO_BLOCKLISTS=0
DO_INSTALL_DEPS=0
DO_VERIFY=0
DO_ROLLBACK=0
BACKUP_DIR=""

# Public abuse/drop lists. Private, reserved, documentation and LAN ranges are
# filtered out before loading so local DNS/LAN traffic keeps working.
BLOCKLIST_URLS=(
  "https://www.spamhaus.org/drop/drop.txt"
  "https://www.spamhaus.org/drop/edrop.txt"
  "https://lists.blocklist.de/lists/all.txt"
  "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
)

usage() {
  cat <<EOF
Uso: sudo bash $SCRIPT_NAME [opcoes]

Perfil: default deny incoming / allow outgoing / deny routed (sem excecoes de entrada).

Opcoes:
  --baseline      aplica o baseline ufw (faz backup e reset das regras atuais)
  --blocklists    baixa listas publicas, carrega no ipset e adiciona regras DROP
  --all           baseline + blocklists
  --verify        mostra ufw, ipset, listeners e teste de saida
  --rollback      restaura o backup mais recente
  --install-deps  instala ipset e curl via pacman (Arch)
  -y, --yes       nao pedir confirmacao no reset
  -h, --help      esta ajuda

Recomendado: sudo bash $SCRIPT_NAME --all
EOF
}

log() { printf '[bb-firewall] %s\n' "$*"; }
die() { printf '[bb-firewall] ERRO: %s\n' "$*" >&2; exit 1; }
need_root() { [[ "${EUID}" -eq 0 ]] || die "rode com sudo: sudo bash $SCRIPT_NAME ..."; }

make_backup() {
  BACKUP_DIR="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BACKUP_DIR"
  ufw status verbose > "$BACKUP_DIR/ufw-status.txt" 2>&1 || true
  cp -a /etc/default/ufw "$BACKUP_DIR/default-ufw" 2>/dev/null || true
  cp -a /etc/ufw "$BACKUP_DIR/ufw-dir" 2>/dev/null || true
  ipset save > "$BACKUP_DIR/ipset.txt" 2>/dev/null || true
  log "backup salvo em $BACKUP_DIR"
}

apply_baseline() {
  need_root
  make_backup

  if [[ "${ASSUME_YES}" -ne 1 ]]; then
    local ans
    read -r -p "Isso vai RESETAR todas as regras ufw atuais. Continuar? [s/N] " ans || die "sem resposta"
    [[ "${ans,,}" == "s" ]] || die "cancelado pelo usuario"
  fi

  ufw --force reset
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw

  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed
  ufw logging low

  # ufw ja permite loopback por padrao; explicitar para evitar duvida
  ufw allow in on lo
  ufw allow out on lo

  ufw --force enable
  log "baseline aplicado (deny in / allow out / deny routed)"
}

insert_ufw_rules() {
  local f="/etc/ufw/before.rules"
  cp -a "$f" "${f}.bb-bak" 2>/dev/null || true
  sed -i "/${MARK_BEGIN}/,/${MARK_END}/d" "$f"

  awk -v begin="$MARK_BEGIN" -v end="$MARK_END" -v set="$IPSET_SET" '
    /^COMMIT[[:space:]]*$/ && !done {
      print begin
      print "-A ufw-before-input  -m set --match-set " set " src -j DROP"
      print "-A ufw-before-output -m set --match-set " set " dst -j DROP"
      print end
      done=1
    }
    { print }
  ' "$f" > "${f}.new"
  mv "${f}.new" "$f"
  ufw reload
  log "regras ipset inseridas em $f"
}

install_ipset_service() {
  local ipset_bin
  ipset_bin="$(command -v ipset)"

  cat > /etc/systemd/system/bb-ipset.service <<EOF
[Unit]
Description=Restaurar ipset de blocklist (bug bounty)
Before=ufw.service
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${ipset_bin} restore -file /etc/ipset.conf -exist

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable bb-ipset.service >/dev/null 2>&1 || true
  log "servico bb-ipset instalado (restaura antes do ufw)"
}

install_blocklists() {
  need_root
  command -v ipset >/dev/null || die "ipset ausente. Rode: sudo bash $SCRIPT_NAME --install-deps"
  command -v curl >/dev/null || die "curl ausente. Rode: sudo bash $SCRIPT_NAME --install-deps"

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  : > "$tmp/raw.txt"
  local url
  for url in "${BLOCKLIST_URLS[@]}"; do
    log "baixando $url"
    if ! curl -fsSL --max-time 30 --retry 2 "$url" >> "$tmp/raw.txt"; then
      log "AVISO: falha ao baixar $url (listas restantes serao usadas)"
    fi
  done

  sed -E 's/;.*$//; s/#.*$//' "$tmp/raw.txt" \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
    | sort -u > "$tmp/all.txt"

  # Remove private, reserved, documentation and local networks.
  grep -Ev '^(0\.|10\.|100\.6[4-9]\.|100\.(1[01][0-9]|12[0-7])\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.18\.|198\.51\.100\.|203\.0\.113\.|224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.|240\.)' \
    "$tmp/all.txt" > "$tmp/public.txt"

  local count
  count="$(wc -l < "$tmp/public.txt")"
  [[ "${count}" -gt 0 ]] || die "listas vazias apos filtro — abortando"

  ipset create "$IPSET_SET" hash:net -exist
  ipset flush "$IPSET_SET"
  while IFS= read -r cidr; do
    ipset add "$IPSET_SET" "$cidr" -exist 2>/dev/null || true
  done < "$tmp/public.txt"

  ipset save > /etc/ipset.conf
  insert_ufw_rules
  install_ipset_service
  log "${count} redes publicas carregadas em $IPSET_SET"
  log "reinicio preserva as listas via bb-ipset.service"
}

install_deps() {
  need_root
  pacman -S --needed --noconfirm ipset curl
}

verify() {
  need_root
  log "=== ufw ==="
  ufw status verbose || true
  log "=== ipset ($IPSET_SET) ==="
  if ipset list "$IPSET_SET" >/dev/null 2>&1; then
    ipset list "$IPSET_SET" | head -12
  else
    log "ipset $IPSET_SET nao carregado"
  fi
  log "=== listeners nao-loopback ==="
  ss -lntup 2>/dev/null | grep -Ev '127\.0\.0\.1|\[::1\]' || true
  log "=== teste de saida ==="
  if curl -fsS --max-time 10 https://ifconfig.me/ip; then
    printf '\n'
  else
    log "teste de saida falhou"
  fi
}

rollback() {
  need_root
  local latest
  latest="$(ls -1dt "${BACKUP_ROOT}"/* 2>/dev/null | head -1 || true)"
  [[ -n "$latest" ]] || die "nenhum backup em $BACKUP_ROOT"

  log "restaurando $latest"
  ufw --force reset
  if [[ -f "$latest/default-ufw" ]]; then
    cp -a "$latest/default-ufw" /etc/default/ufw
  fi
  if [[ -d "$latest/ufw-dir" ]]; then
    cp -a "$latest/ufw-dir/." /etc/ufw/
  fi
  if [[ -f "$latest/ipset.txt" ]]; then
    ipset restore -file "$latest/ipset.txt" -exist 2>/dev/null || true
  fi

  if grep -q '^Status: active' "$latest/ufw-status.txt" 2>/dev/null; then
    ufw --force enable
  else
    ufw disable
  fi
  ufw status verbose
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --baseline) DO_BASELINE=1 ;;
    --blocklists) DO_BLOCKLISTS=1 ;;
    --all) DO_BASELINE=1; DO_BLOCKLISTS=1 ;;
    --verify) DO_VERIFY=1 ;;
    --rollback) DO_ROLLBACK=1 ;;
    --install-deps) DO_INSTALL_DEPS=1 ;;
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "opcao desconhecida: $1" ;;
  esac
  shift
done

if [[ "$DO_BASELINE" -eq 0 && "$DO_BLOCKLISTS" -eq 0 && "$DO_VERIFY" -eq 0 \
      && "$DO_ROLLBACK" -eq 0 && "$DO_INSTALL_DEPS" -eq 0 ]]; then
  usage
  exit 0
fi

if [[ "$DO_INSTALL_DEPS" -eq 1 ]]; then install_deps; fi
if [[ "$DO_BASELINE" -eq 1 ]]; then apply_baseline; fi
if [[ "$DO_BLOCKLISTS" -eq 1 ]]; then install_blocklists; fi
if [[ "$DO_ROLLBACK" -eq 1 ]]; then rollback; fi
if [[ "$DO_VERIFY" -eq 1 ]]; then verify; fi
