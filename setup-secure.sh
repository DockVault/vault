#!/usr/bin/env bash
#
# One-shot setup for a STANDALONE, HTTPS-only vault deployment (e.g. a personal
# Azure VM). It is IDEMPOTENT and does everything for you:
#   - first run:  collects settings, writes ./.env (secrets), generates ./certs,
#                 builds the image and starts the stack;
#   - re-run:     REUSES the existing ./.env (keeps your data + at-rest key),
#                 REBUILDS the image and RECREATES the containers so any code or
#                 compose change is picked up — without touching your data.
#
# Only encrypted listeners are ever published:
#   443  HTTPS      (TLS terminates inside the container — uvicorn ssl)
#   2322 SFTP/SSH   (optional)
#
# Usage (from this directory, on the Linux host, as root):
#   sudo ./setup-secure.sh                 first run OR rebuild-in-place (the common case)
#   sudo ./setup-secure.sh --certs-only    (re)generate certs only, then restart vault-api
#   sudo ./setup-secure.sh --no-cache      rebuild the image from scratch (no build cache)
#   sudo ./setup-secure.sh --no-start      do setup/certs but don't build or start
#   sudo ./setup-secure.sh --help
#
# Fully unattended first run — preset the answers as env vars (nothing is asked):
#   sudo -E env SERVER_NAME=vault.example.com CERT_MODE=1 \
#        ADMIN_USERNAME=admin ADMIN_EMAIL=admin@example.com \
#        ADMIN_PASSWORD='a-strong-password' WANT_SFTP=0 \
#        ./setup-secure.sh
#   (CERT_MODE: 1=self-signed  2=Let's Encrypt [+ACME_EMAIL]  3=bring-your-own [+BYO_CERT/BYO_KEY])
#
# SAFETY: an existing ./.env is REUSED, never overwritten. ENCRYPTION_KEY (the
# at-rest master key) lives there — regenerating it makes every already-stored
# file permanently undecryptable. To start TRULY fresh (this DESTROYS data):
#   move ./.env aside AND run:
#     docker compose -f docker-compose.secure.yml down -v

set -euo pipefail

cd "$(dirname "$0")"

COMPOSE_FILE="docker-compose.secure.yml"
CERT_DIR="certs"
APP_UID=10001            # "appuser" inside the image (Dockerfile USER); certs must be readable by it
APP_DIR="$(pwd)"

# Scratch dir for key material in flight; cleaned up on ANY exit (incl. set -e).
TMP_DIR=""
trap 'if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi' EXIT

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- arguments
CERTS_ONLY=0
NO_CACHE=0
NO_START=0
for _arg in "$@"; do
  case "$_arg" in
    --certs-only) CERTS_ONLY=1 ;;
    --no-cache)   NO_CACHE=1 ;;
    --no-start)   NO_START=1 ;;
    -h|--help)
      sed -n '2,/^set -euo/{/^set -euo/!p}' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown argument '$_arg' (see --help)" ;;
  esac
done

# TTY? We only *need* one when we have to ask a first-run question. A re-run
# (existing .env, certs present) asks nothing, so it works from cron/automation.
INTERACTIVE=1
[ -t 0 ] || INTERACTIVE=0

# ---------------------------------------------------------------- helpers
prompt() { # prompt <var> <question> [default]
  local _var="$1" _q="$2" _d="${3:-}" _r
  if [ -n "$_d" ]; then
    read -rp "$_q [$_d]: " _r; _r="${_r:-$_d}"
  else
    while :; do read -rp "$_q: " _r; [ -n "$_r" ] && break; say "  (required)"; done
  fi
  printf -v "$_var" '%s' "$_r"
}

# ask <var> <question> [default] — resolve a value without clobbering a preset env
# var: if $<var> is already set, keep it; else prompt (TTY) / use default / die.
ask() {
  local _var="$1" _q="$2" _d="${3:-}"
  [ -n "${!_var:-}" ] && return 0
  if [ "$INTERACTIVE" -eq 1 ]; then
    prompt "$_var" "$_q" "$_d"
  elif [ -n "$_d" ]; then
    printf -v "$_var" '%s' "$_d"
  else
    die "non-interactive and \$$_var is not set (needed: $_q)"
  fi
}

confirm() { # confirm <question> [default Y|N] -> 0=yes
  local _r _d="${2:-Y}"
  if [ "$_d" = "N" ]; then
    read -rp "$1 [y/N]: " _r
    case "$_r" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
  fi
  read -rp "$1 [Y/n]: " _r
  case "$_r" in n|N|no|NO) return 1 ;; *) return 0 ;; esac
}

is_ipv4() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }

# Fernet key = urlsafe-base64 of 32 random bytes; equivalent to
# python: base64.urlsafe_b64encode(os.urandom(32))
gen_fernet_key() { openssl rand -base64 32 | tr '+/' '-_'; }

# read_env <KEY> — echo the value of KEY from ./.env (first match), empty if
# absent. Tolerates BOTH quoted ('..'/".." — what this script writes) AND UNquoted
# values (KEY=value — the .env.example / dotenv convention, and the format of the
# repo's real .env). Getting this wrong made a re-run mis-read a valid .env as
# "incomplete" and dangle a data-destroying `down -v`. Pipefail-safe (no `| head`).
read_env() {
  [ -f .env ] || return 0
  local _v
  _v="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env)"
  _v="${_v%%$'\n'*}"     # first match only
  _v="${_v%$'\r'}"       # tolerate CRLF .env
  case "$_v" in          # strip one surrounding matching quote pair
    \'*\') _v="${_v#\'}"; _v="${_v%\'}" ;;
    \"*\") _v="${_v#\"}"; _v="${_v%\"}" ;;
  esac
  printf '%s' "$_v"
}

# cert_cn — the CN from ./certs/cert.pem, used only to label the summary when an
# older .env (pre-SERVER_NAME persistence) is reused. Empty if unreadable.
cert_cn() {
  [ -f "$CERT_DIR/cert.pem" ] || return 0
  local _s
  _s="$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -subject 2>/dev/null || true)"
  printf '%s' "$_s" | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,/]*\).*/\1/p'
}

# _remapped_engine — true if the Docker engine remaps container uids to host
# SUBORDINATE uids (rootless, OR rootful with --userns-remap). In that case the
# in-container appuser (uid 10001) is NOT host uid 10001, so a host-10001-owned
# mode-600 key is unreadable inside the container and TLS silently won't start —
# the certs must be world-readable instead. Only ever call this inside `if`.
_remapped_engine() {
  docker info --format '{{join .SecurityOptions ","}}' 2>/dev/null | grep -Eq 'rootless|name=userns'
}

# Make ./certs/{cert.pem,key.pem} readable by the in-container app (uid 10001),
# which reads them through a read-only bind mount.
#
# The container uid has no matching /etc/passwd name on the host, so we chown by
# NUMERIC id — NOT `install -o <name>`, which rejected the bare uid on some hosts
# with "install: invalid user: '10001'". `install -m` (mode only) sets the mode
# atomically at copy time so the private key is never briefly world-readable. If
# numeric chown is somehow refused, fall back to world-readable (single-tenant
# host) so the container can still start, with a loud warning.
put_cert() { # put_cert <src-cert(fullchain).pem> <src-key.pem>
  local _cert="$1" _key="$2"
  # Refuse passphrase-protected keys up front: uvicorn is given no passphrase
  # (api_server.py passes only ssl_certfile/ssl_keyfile), so an encrypted key can
  # never serve — and openssl would stop to prompt for it mid-script.
  if grep -q 'ENCRYPTED' "$_key"; then
    die "the private key '$_key' is passphrase-protected and uvicorn cannot load it.
       Decrypt it first:  openssl pkey -in '$_key' -out key-decrypted.pem"
  fi
  # Refuse silently mismatched pairs (works for RSA and EC keys).
  local _certpub _keypub
  _certpub="$(openssl x509 -in "$_cert" -pubkey -noout)" || die "cannot parse certificate '$_cert'"
  _keypub="$(openssl pkey -in "$_key" -pubout)"          || die "cannot parse private key '$_key'"
  [ "$_certpub" = "$_keypub" ] || die "certificate and key do not match"

  install -d -m 700 "$CERT_DIR"
  install    -m 644 "$_cert" "$CERT_DIR/cert.pem"
  install    -m 600 "$_key"  "$CERT_DIR/key.pem"
  apply_cert_owner
}

# Pick a LOCALLY-PRESENT image (with /bin/sh + /bin/cat) for the cert-permission helper below. We do
# NOT pull (air-gap friendly); prints nothing + returns non-zero if none is present, so the caller
# keeps the world-readable fallback.
_local_helper_image() {
  local _i
  for _i in dockvault-vault:latest busybox alpine postgres:15-alpine redis:7-alpine; do
    docker image inspect "$_i" >/dev/null 2>&1 && { printf '%s' "$_i"; return 0; }
  done
  return 1
}

# Best-effort: the HOST uid that the container's APP_UID maps to under a userns-REMAP engine, resolved
# from /etc/subuid. A container CANNOT chown a host-root-owned bind-mounted file (it shows as `nobody`
# inside the userns), so the chown must be done here by host root — which needs the mapped uid. Only the
# userns-remap case is resolvable from the host (rootless needs the daemon-user's subuid + a different
# offset and is deliberately left to the world-readable fallback). Prints the uid, or nothing on failure.
_remapped_key_owner() {
  docker info --format '{{join .SecurityOptions ","}}' 2>/dev/null | grep -q 'name=userns' || return 1
  local _u=dockremap _base _v
  if [ -r /etc/docker/daemon.json ]; then
    _v="$(sed -nE 's/.*"userns-remap"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' /etc/docker/daemon.json 2>/dev/null | head -n1)"
    case "$_v" in ""|default) _u=dockremap ;; *:*) _u="${_v%%:*}" ;; *) _u="$_v" ;; esac
  fi
  _base="$(awk -F: -v u="$_u" '$1==u{print $2; exit}' /etc/subuid 2>/dev/null)"
  case "$_base" in ''|*[!0-9]*) return 1 ;; esac
  [ "$_base" -ge 1000 ] || return 1     # sanity: a subuid base is never a low/system uid
  printf '%s' "$(( _base + APP_UID ))"
}

# On a userns-remap engine, chown the certs (as host root) to the container's MAPPED host uid + keep the
# key at mode 600 (dir 700), then VERIFY — by running a container as APP_UID that cat's the key — that the
# vault process can actually read it. Returns 0 ONLY if that is proven; every failure path (unresolvable
# mapping, rootless, chown fails, no local image to verify, verify fails) returns non-zero, so the caller
# falls back to the world-readable key and TLS can never break. $1 = absolute certs dir.
_tighten_certs_for_remapped_engine() {
  local _cd="$1" _muid _img
  _muid="$(_remapped_key_owner)" || return 1
  chown "$_muid:$_muid" "$_cd" "$_cd/key.pem" "$_cd/cert.pem" 2>/dev/null || return 1
  chmod 700 "$_cd" && chmod 600 "$_cd/key.pem" && chmod 644 "$_cd/cert.pem" || return 1
  _img="$(_local_helper_image)" || return 1   # require verification; don't trust an unproven mapping
  docker run --rm -u "$APP_UID" --entrypoint /bin/cat -v "$_cd:/c:ro" "$_img" /c/key.pem >/dev/null 2>&1 || return 1
  return 0
}

# Give the cert dir + files to uid 10001 (numeric), else fall back to
# world-readable so the container can read them regardless. Idempotent, so a
# re-run also REPAIRS certs left root-owned by an older/failed install.
apply_cert_owner() {
  chmod 700 "$CERT_DIR" 2>/dev/null || true
  chmod 644 "$CERT_DIR/cert.pem" 2>/dev/null || true
  chmod 600 "$CERT_DIR/key.pem"  2>/dev/null || true
  if _remapped_engine; then
    # Rootless / userns-remapped engine: the container's appuser is a REMAPPED subordinate uid, not
    # host uid 10001, so chowning to HOST 10001 leaves the key unreadable in the container. Prefer to
    # have a container chown the key to APP_UID (engine-translated to the right host uid) and KEEP mode
    # 600, verified readable; only if that can't be proven do we widen the key to world-readable.
    if _tighten_certs_for_remapped_engine "$APP_DIR/$CERT_DIR"; then
      say "  certs owned by the container's mapped uid (key mode 600, NOT world-readable)"
    else
      chmod 755 "$CERT_DIR"
      chmod 644 "$CERT_DIR/key.pem"
      warn "rootless/userns Docker: could not tighten the TLS key to the container's mapped uid (no local"
      warn "helper image yet, or the engine refused), so $CERT_DIR/key.pem is world-readable (644). Host"
      warn "assumed SINGLE-TENANT; on a shared host restrict $CERT_DIR (dedicated user + ACLs) or use"
      warn "rootful Docker. Re-run 'sudo ./setup-secure.sh --certs-only' once the stack is up to retry."
    fi
  elif chown "$APP_UID:$APP_UID" "$CERT_DIR" "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem" 2>/dev/null \
       && [ "$(stat -c '%u' "$CERT_DIR/key.pem" 2>/dev/null || echo x)" = "$APP_UID" ]; then
    say "  certs owned by uid $APP_UID (key mode 600)"
  else
    # Could not set numeric ownership. Make them readable by the container uid via
    # world-read instead; the dir must stay traversable (o+x).
    chmod 755 "$CERT_DIR"
    chmod 644 "$CERT_DIR/key.pem"
    warn "could not chown certs to uid $APP_UID; set them world-readable so the"
    warn "container can read them (host assumed single-tenant). Private key is at"
    warn "$CERT_DIR/key.pem mode 644 — restrict host access accordingly."
  fi
}

# Warn (don't fail) about the two things that break `up` on port 443.
preflight_ports() {
  local _secopts
  _secopts="$(docker info --format '{{join .SecurityOptions ","}}' 2>/dev/null || true)"
  if printf '%s' "$_secopts" | grep -q 'rootless'; then
    # Only a real problem when the unprivileged-port floor is above 443; if the
    # operator already lowered it, publishing 443 works fine on rootless.
    local _floor
    _floor="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
    if [ "${_floor:-1024}" -gt 443 ]; then
      say ""
      warn "this Docker engine is ROOTLESS and the unprivileged-port floor is $_floor (>443),"
      warn "so publishing host port 443 WILL fail with \"unable to listen on 443\". Fix it"
      warn "BEFORE this run (Redis/Postgres/SFTP would come up but the web app would not):"
      warn "  * allow the privileged bind:   sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443"
      warn "    (persist: echo 'net.ipv4.ip_unprivileged_port_start=443' | sudo tee /etc/sysctl.d/99-vault.conf)"
      warn "  * OR run against a ROOTFUL daemon:   docker context use default"
      say ""
    fi
  fi
  if command -v ss >/dev/null 2>&1; then
    if ss -H -ltn 2>/dev/null | grep -Eq '[^0-9]:443[[:space:]]'; then
      warn "something is already LISTENING on host port 443 — the container will not"
      warn "be able to bind it. Free 443 first (find it with:  sudo ss -ltnp 'sport = :443')."
      say ""
    fi
  fi
}

# ---------------------------------------------------------------- preconditions
[ "$(id -u)" -eq 0 ] || die "run as root: sudo ./setup-secure.sh (needed for docker, chown of $CERT_DIR/, and optionally certbot)"
command -v openssl >/dev/null 2>&1 || die "openssl not found"
command -v docker  >/dev/null 2>&1 || die "docker not found (install: curl -fsSL https://get.docker.com | sh)"
docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is not available"
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon (is it running? are you on the right 'docker context'?)"
[ -f "$COMPOSE_FILE" ] || die "$COMPOSE_FILE not found — run this script from the repository root (where $COMPOSE_FILE lives)"

HAVE_ENV=0
[ -f .env ] && HAVE_ENV=1
HAVE_CERTS=0
[ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/key.pem" ] && HAVE_CERTS=1

# An existing .env must carry the secrets the compose file demands, or `up` will
# fail late with a cryptic "missing" interpolation error. Fail early + clearly.
if [ "$HAVE_ENV" -eq 1 ]; then
  for _k in ENCRYPTION_KEY JWT_SECRET_KEY VAULT_DB_PASSWORD; do
    [ -n "$(read_env "$_k")" ] || die ".env exists but is missing $_k — it looks incomplete/corrupt.
       Fix it, or (DESTROYS data) move .env aside + 'docker compose -f $COMPOSE_FILE down -v' and re-run."
  done
fi

# ---------------------------------------------------------------- cert helpers
choose_cert_mode() {
  # Resolves CERT_MODE (1/2/3). Reuses a value from env or .env; else asks.
  [ -n "${CERT_MODE:-}" ] || CERT_MODE="$(read_env CERT_MODE)"
  if [ -z "${CERT_MODE:-}" ]; then
    if [ "$INTERACTIVE" -eq 1 ]; then
      say ""
      say "Certificate source:"
      say "  1) Self-signed   — works immediately, browsers warn until you trust it (fine for personal use)"
      say "  2) Let's Encrypt — real trusted cert; REQUIRES a public DNS name pointing at this VM,"
      say "                     with port 80 reachable (ACME challenge + auto-renewals)"
      say "  3) Bring your own — you already have a fullchain cert + key on this machine"
      prompt CERT_MODE "Choose 1/2/3" "1"
    else
      CERT_MODE=1
    fi
  fi
  case "$CERT_MODE" in 1|2|3) ;; *) die "invalid CERT_MODE '$CERT_MODE' (1, 2 or 3)" ;; esac
  if [ "$CERT_MODE" = "2" ] && is_ipv4 "$SERVER_NAME"; then
    die "Let's Encrypt cannot issue for a bare IP ($SERVER_NAME) — use a DNS name, or pick self-signed (1)"
  fi
}

generate_certs() {
  # Requires SERVER_NAME (+ CERT_MODE resolved via choose_cert_mode).
  say ""
  case "$CERT_MODE" in
    1)
      say "Generating a self-signed certificate for $SERVER_NAME (RSA 4096, 825 days) ..."
      local _san
      if is_ipv4 "$SERVER_NAME"; then _san="IP:$SERVER_NAME"; else _san="DNS:$SERVER_NAME"; fi
      TMP_DIR="$(mktemp -d)"
      # stderr deliberately NOT suppressed: if openssl fails (e.g. no -addext on
      # an ancient release) the reason must be visible. Cleanup rides the EXIT trap.
      openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
        -keyout "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" \
        -subj "/CN=$SERVER_NAME" -addext "subjectAltName=$_san"
      put_cert "$TMP_DIR/cert.pem" "$TMP_DIR/key.pem"
      rm -rf "$TMP_DIR"; TMP_DIR=""
      ;;
    2)
      say "Obtaining a Let's Encrypt certificate for $SERVER_NAME ..."
      ask ACME_EMAIL "Email for Let's Encrypt expiry notices" "${ADMIN_EMAIL:-$(read_env ADMIN_EMAIL)}"
      [ -n "${ACME_EMAIL:-}" ] || ACME_EMAIL="admin@example.com"
      if ! command -v certbot >/dev/null 2>&1; then
        say "  installing certbot ..."
        # Two statements on purpose: inside `a && b`, a failure of `a` is EXEMPT
        # from set -e and the script would fall through to a confusing
        # "certbot: command not found" later.
        apt-get update -qq || die "apt-get update failed"
        apt-get install -y -qq certbot || die "certbot installation failed"
      fi
      # Standalone http-01: certbot binds port 80 itself for the challenge. This
      # is the only moment anything answers unencrypted, it serves ACME challenge
      # tokens only (never app traffic), and port 80 must be open in the Azure NSG
      # for issuance AND future auto-renewals.
      certbot certonly --standalone --non-interactive --agree-tos \
        -m "$ACME_EMAIL" -d "$SERVER_NAME"
      put_cert "/etc/letsencrypt/live/$SERVER_NAME/fullchain.pem" \
               "/etc/letsencrypt/live/$SERVER_NAME/privkey.pem"
      install_renewal_hook
      ;;
    3)
      ask BYO_CERT "Path to the certificate (FULLCHAIN, PEM)"
      ask BYO_KEY  "Path to the private key (PEM)"
      [ -f "$BYO_CERT" ] || die "no such file: $BYO_CERT"
      [ -f "$BYO_KEY"  ] || die "no such file: $BYO_KEY"
      put_cert "$BYO_CERT" "$BYO_KEY"
      ;;
  esac
}

install_renewal_hook() {
  # Auto-renewal (certbot's systemd timer runs ~twice daily): copy the renewed
  # cert into ./certs and restart vault-api — uvicorn does not hot-reload certs.
  local _hook="/etc/letsencrypt/renewal-hooks/deploy/dockvault-vault.sh"
  mkdir -p "$(dirname "$_hook")"
  # Staged + pair-validated + atomic mv: certbot mints a NEW private key each
  # renewal, so a partial copy must never leave a mismatched cert/key pair
  # (uvicorn would crash-loop on the next vault-api restart). Ownership mirrors
  # apply_cert_owner: on a rootless/userns-remapped engine (or if numeric chown
  # fails) the key is made world-readable so the container's uid can read it, and
  # that downgrade is logged to syslog (the hook runs headless — no TTY to warn).
  cat > "$_hook" <<EOF
#!/bin/bash
# Written by setup-secure.sh — deploys a renewed Let's Encrypt cert into the
# vault stack at $APP_DIR and restarts the API so uvicorn picks it up.
set -e
CD="$APP_DIR/$CERT_DIR"
install -m 644 "/etc/letsencrypt/live/$SERVER_NAME/fullchain.pem" "\$CD/.new-cert.pem"
install -m 600 "/etc/letsencrypt/live/$SERVER_NAME/privkey.pem"   "\$CD/.new-key.pem"
# Preserve whatever ownership + mode apply_cert_owner already established on the LIVE key onto the
# renewed key, so a renewal keeps the tightened (mode 600, mapped-uid-owned) OR the world-readable
# fallback state without re-resolving the userns mapping here. cert.pem is public -> always 644.
_own="\$(stat -c '%u:%g' "\$CD/key.pem" 2>/dev/null || echo 0:0)"
_mode="\$(stat -c '%a' "\$CD/key.pem" 2>/dev/null || echo 644)"
chown "\$_own" "\$CD/.new-key.pem" "\$CD/.new-cert.pem" 2>/dev/null || true
chmod "\$_mode" "\$CD/.new-key.pem" 2>/dev/null || chmod 644 "\$CD/.new-key.pem"
chmod 644 "\$CD/.new-cert.pem"
logger -t dockvault-vault "renewed TLS key perms mirrored from live key (mode \$_mode)" 2>/dev/null || true
[ "\$(openssl x509 -in "\$CD/.new-cert.pem" -pubkey -noout)" = "\$(openssl pkey -in "\$CD/.new-key.pem" -pubout)" ]
mv "\$CD/.new-key.pem"  "\$CD/key.pem"
mv "\$CD/.new-cert.pem" "\$CD/cert.pem"
cd "$APP_DIR" && docker compose -f "$COMPOSE_FILE" restart vault-api
EOF
  chmod +x "$_hook"
  say "  renewal deploy hook installed: $_hook"
}

# ================================================================ --certs-only
if [ "$CERTS_ONLY" -eq 1 ]; then
  [ "$HAVE_ENV" -eq 1 ] || die "no ./.env yet — run a full setup first (sudo ./setup-secure.sh)"
  SERVER_NAME="${SERVER_NAME:-$(read_env SERVER_NAME)}"
  ask SERVER_NAME "Public DNS name (or public IP) clients will use, e.g. vault.example.com"
  [[ "$SERVER_NAME" =~ [[:space:]] ]] && die "'$SERVER_NAME' contains whitespace"
  choose_cert_mode
  generate_certs
  if docker inspect vault-api >/dev/null 2>&1; then
    say ""
    say "Restarting vault-api to pick up the new certificate ..."
    docker compose -f "$COMPOSE_FILE" restart vault-api
  else
    say ""
    say "The stack is not running yet. Start it with:  sudo ./setup-secure.sh"
  fi
  say "Done (certs only)."
  exit 0
fi

# ================================================================ full setup
say ""
say "=== DockVault vault — standalone HTTPS-only setup ==="

if [ "$HAVE_ENV" -eq 1 ]; then
  # ------- RE-RUN: reuse existing secrets, rebuild + recreate, keep data -------
  say ""
  say "Existing ./.env found — REUSING it (keeping ENCRYPTION_KEY and all your data)."
  say "This run will rebuild the image and recreate the containers to apply changes."
  chmod 600 .env 2>/dev/null || true   # a reused/hand-created .env may be looser; it holds secrets
  ADMIN_USERNAME="$(read_env ADMIN_USERNAME)"
  grep -Eq '^COMPOSE_PROFILES=.*\bsftp\b' .env && WANT_SFTP=1 || WANT_SFTP=0
  ADMIN_PW_GENERATED=0
  SERVER_NAME="$(read_env SERVER_NAME)"
  if [ "$HAVE_CERTS" -eq 1 ]; then
    say ""
    say "Certificates already present — keeping them (repairing ownership if needed)."
    say "  (regenerate later with:  sudo ./setup-secure.sh --certs-only)"
    apply_cert_owner
  else
    warn "no certificates found in ./$CERT_DIR — generating them now."
    ask SERVER_NAME "Public DNS name (or public IP) clients will use, e.g. vault.example.com"
    [[ "$SERVER_NAME" =~ [[:space:]] ]] && die "'$SERVER_NAME' contains whitespace"
    choose_cert_mode
    generate_certs
  fi
else
  # ------- FIRST RUN: gather settings, generate secrets, write .env, certs -----
  ask SERVER_NAME "Public DNS name (or public IP) clients will use, e.g. vault.example.com"
  [[ "$SERVER_NAME" =~ [[:space:]] ]] && die "'$SERVER_NAME' contains whitespace"
  choose_cert_mode

  # Values land single-quoted in .env — a single quote in them breaks compose's
  # dotenv parse, so reject it early (same guard as the password).
  ask ADMIN_USERNAME "Admin username" "admin"
  case "$ADMIN_USERNAME" in *"'"*) die "ADMIN_USERNAME must not contain a single-quote (dotenv quoting)" ;; esac
  ask ADMIN_EMAIL "Admin email" "admin@example.com"
  case "$ADMIN_EMAIL" in *"'"*) die "ADMIN_EMAIL must not contain a single-quote (dotenv quoting)" ;; esac

  ADMIN_PW_GENERATED=0
  if [ -n "${ADMIN_PASSWORD:-}" ]; then
    case "$ADMIN_PASSWORD" in *"'"*) die "ADMIN_PASSWORD must not contain a single-quote (dotenv quoting)" ;; esac
    [ "${#ADMIN_PASSWORD}" -ge 10 ] || die "ADMIN_PASSWORD must be at least 10 characters"
  elif [ "$INTERACTIVE" -eq 1 ]; then
    while :; do
      IFS= read -rsp "Admin password (leave empty to auto-generate): " _pw1; say ""
      if [ -z "$_pw1" ]; then
        ADMIN_PASSWORD="$(openssl rand -hex 12)"; ADMIN_PW_GENERATED=1; break
      fi
      case "$_pw1" in *"'"*) say "  no single-quote characters, please (dotenv quoting)"; continue ;; esac
      [ "${#_pw1}" -ge 10 ] || { say "  use at least 10 characters"; continue; }
      IFS= read -rsp "Confirm admin password: " _pw2; say ""
      [ "$_pw1" = "$_pw2" ] || { say "  passwords do not match — try again"; continue; }
      ADMIN_PASSWORD="$_pw1"; break
    done
  else
    ADMIN_PASSWORD="$(openssl rand -hex 12)"; ADMIN_PW_GENERATED=1
  fi

  # SFTP: default NO (posture is "port 443 only"). SFTP is SSH-encrypted but adds
  # a second published port (2322) — opt in explicitly.
  if [ -z "${WANT_SFTP:-}" ]; then
    if [ "$INTERACTIVE" -eq 1 ] && confirm "Enable SFTP (SSH-encrypted, publishes a SECOND port, 2322)?" N; then
      WANT_SFTP=1
    else
      WANT_SFTP=0
    fi
  fi
  case "$WANT_SFTP" in 1|true|yes|on|Y|y) WANT_SFTP=1 ;; *) WANT_SFTP=0 ;; esac

  say ""
  say "Generating secrets and writing .env ..."
  ENCRYPTION_KEY="$(gen_fernet_key)"
  JWT_SECRET_KEY="$(openssl rand -hex 32)"
  VAULT_DB_PASSWORD="$(openssl rand -hex 16)"
  REDIS_PASSWORD="$(openssl rand -hex 24)"

  umask 077
  {
    printf '%s\n' "# Generated by setup-secure.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ) for https://$SERVER_NAME/"
    printf '%s\n' "#"
    printf '%s\n' "# *** BACK THIS FILE UP somewhere off this VM (password manager). ***"
    printf '%s\n' "# ENCRYPTION_KEY is the at-rest master key: without it, every stored"
    printf '%s\n' "# file (and any backup of the storage volume) is permanently unreadable."
    printf '%s\n' "ENCRYPTION_KEY='$ENCRYPTION_KEY'"
    printf '%s\n' "JWT_SECRET_KEY='$JWT_SECRET_KEY'"
    printf '%s\n' "VAULT_DB_PASSWORD='$VAULT_DB_PASSWORD'"
    printf '%s\n' "ADMIN_USERNAME='$ADMIN_USERNAME'"
    printf '%s\n' "ADMIN_EMAIL='$ADMIN_EMAIL'"
    printf '%s\n' "ADMIN_PASSWORD='$ADMIN_PASSWORD'"
    printf '%s\n' "# Redis AUTH on the login-throttle / lockout / session-hash store. Redis is on the"
    printf '%s\n' "# internal network only, but this is defense-in-depth against a co-tenant on the bridge."
    printf '%s\n' "REDIS_PASSWORD='$REDIS_PASSWORD'"
    printf '%s\n' "# Reject requests carrying an unexpected Host header (defense-in-depth if you later"
    printf '%s\n' "# front the vault with a shared reverse proxy / CDN)."
    printf '%s\n' "ALLOWED_HOSTS='$SERVER_NAME'"
    printf '%s\n' "# Remembered so a re-run / --certs-only can regenerate certs without asking."
    printf '%s\n' "# (The app ignores these — pydantic Settings uses extra='ignore'.)"
    printf '%s\n' "SERVER_NAME='$SERVER_NAME'"
    printf '%s\n' "CERT_MODE='$CERT_MODE'"
    if [ "$WANT_SFTP" -eq 1 ]; then
      printf '%s\n' "# Activates the vault-sftp service in docker-compose.secure.yml."
      printf '%s\n' "COMPOSE_PROFILES=sftp"
    fi
  } > .env
  umask 022
  say "  wrote .env (mode 600)"

  generate_certs
fi

# ---------------------------------------------------------------- build + start
if [ "$NO_START" -eq 1 ]; then
  say ""
  say "Setup + certs done. Skipping build/start (--no-start). Start later with:"
  say "  sudo ./setup-secure.sh"
  exit 0
fi

preflight_ports

say ""
say "Building the image and (re)creating the stack ..."
# --build            : rebuild the image so code/Dockerfile changes are applied.
# --force-recreate   : recreate containers even if unchanged, so compose changes
#                      (env, tmpfs, ports) always take effect.
# --remove-orphans   : drop stray containers from an earlier/failed attempt.
# Data lives in named volumes, which none of these touch — your files + keys stay.
if [ "$NO_CACHE" -eq 1 ]; then
  docker compose -f "$COMPOSE_FILE" build --no-cache
  docker compose -f "$COMPOSE_FILE" up -d --force-recreate --remove-orphans
else
  docker compose -f "$COMPOSE_FILE" up -d --build --force-recreate --remove-orphans
fi

# The tighten-to-mode-600 TLS-key helper in apply_cert_owner needs a local image to VERIFY the key is
# readable, and the first pass above ran BEFORE this build — so on a remapped engine it fell back to
# world-readable. Now that the image exists, re-apply (idempotent; transparent to the running container,
# whose key content is unchanged) so a fresh install lands the mode-600 key in a single pass.
if [ "$HAVE_CERTS" -eq 0 ] && _remapped_engine; then
  say ""
  say "Re-applying certificate ownership now the image is built (tightening the TLS key perms) ..."
  apply_cert_owner
fi

say ""
say "Waiting for vault-api to become healthy (startup migrations run on first boot) ..."
_status=starting
for _i in $(seq 1 40); do
  _status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' vault-api 2>/dev/null || echo missing)"
  case "$_status" in
    healthy)     break ;;
    exited|dead) break ;;   # container gave up — stop waiting, diagnose now
    restarting)             # crash-looping — bail once it's clearly not recovering
      _rc="$(docker inspect -f '{{.RestartCount}}' vault-api 2>/dev/null || echo 0)"
      [ "${_rc:-0}" -ge 3 ] && break ;;
  esac
  sleep 3
done

# The web app is the whole point of this deploy, so a vault-api that isn't serving
# on 443 is a HARD failure — surface the real cause (logs + the two usual culprits)
# and exit non-zero, instead of printing a success summary for a stack that is down.
if [ "$_status" != "healthy" ]; then
  _l443="unknown"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | grep -Eq '[^0-9]:443[[:space:]]' && _l443=yes || _l443=no
  fi
  say ""
  warn "vault-api did NOT come up healthy (state: '$_status'; host :443 listening: $_l443)."
  say ""
  say "  ---- docker compose -f $COMPOSE_FILE logs --tail 40 vault-api ----"
  docker compose -f "$COMPOSE_FILE" logs --tail 40 --no-color vault-api 2>&1 | sed 's/^/    /' || true
  say "  ------------------------------------------------------------------"
  _logs="$(docker compose -f "$COMPOSE_FILE" logs --no-color vault-api 2>&1 || true)"
  _derr="$(docker inspect -f '{{.State.Error}}' vault-api 2>/dev/null || true)"
  say ""
  if printf '%s' "$_logs" | grep -Eqi 'permission denied.*(cert|key|\.pem)|ssl.*(cert|key)|could not.*(read|load).*(cert|key)|no such file.*\.pem'; then
    warn "LIKELY CAUSE: the container can't read the TLS cert/key. On a rootless or"
    warn "userns-remapped engine the host uid doesn't map into the container, so a"
    warn "mode-600 key is unreadable. Fix:  sudo chmod 644 $CERT_DIR/key.pem"
    warn "  (or regenerate:  sudo ./setup-secure.sh --certs-only), then re-run."
    say ""
  fi
  if printf '%s %s' "$_logs" "$_derr" | grep -Eqi 'bind.*443|address already in use|listen tcp.*:443|:443.*permission denied|failed to bind'; then
    warn "LIKELY CAUSE: host port 443 could not be bound. Either something already"
    warn "holds it (find it:  sudo ss -ltnp 'sport = :443'), or this is a ROOTLESS"
    warn "engine that can't bind a privileged port:"
    warn "  sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443   (then re-run)"
    warn "  or use a rootful daemon:  docker context use default"
    say ""
  fi
  die "vault-api is not serving on https/443 — fix the cause above and re-run 'sudo ./setup-secure.sh'.
       (Redis/Postgres/SFTP may be up, but no summary is printed because the web app is down.)"
fi
say "  vault-api is healthy."

# ---------------------------------------------------------------- summary
# Resolve the display name: shell var -> .env -> the cert's CN (covers an older
# .env that predates SERVER_NAME persistence) -> a placeholder, so we never print
# a bare "https:///".
[ -n "${SERVER_NAME:-}" ] || SERVER_NAME="$(read_env SERVER_NAME)"
[ -n "${SERVER_NAME:-}" ] || SERVER_NAME="$(cert_cn)"
[ -n "${SERVER_NAME:-}" ] || SERVER_NAME="<your-server-name>"
[ -n "${WANT_SFTP:-}" ]   || { grep -Eq '^COMPOSE_PROFILES=.*\bsftp\b' .env && WANT_SFTP=1 || WANT_SFTP=0; }
say ""
say "==================================================================="
say " Web UI / API : https://$SERVER_NAME/          (host port 443 only)"
if [ "$WANT_SFTP" = "1" ]; then
  say " SFTP (SSH)   : $SERVER_NAME port 2322"
else
  say " SFTP         : disabled (re-enable: add COMPOSE_PROFILES=sftp to .env, re-run)"
fi
[ -n "${ADMIN_USERNAME:-}" ] && say " Admin login  : $ADMIN_USERNAME"
if [ "${ADMIN_PW_GENERATED:-0}" -eq 1 ]; then
  say " Admin passwd : $ADMIN_PASSWORD   (auto-generated — store it NOW)"
fi
say ""
say " Azure NSG inbound rules needed:"
say "   443/tcp  from anywhere you use the vault (HTTPS)"
say "   22/tcp   from YOUR IP only (VM admin SSH)"
[ "$WANT_SFTP" = "1" ] && say "   2322/tcp from anywhere you use SFTP (SSH-encrypted)"
[ "${CERT_MODE:-$(read_env CERT_MODE)}" = "2" ] && say "   80/tcp   from anywhere (Let's Encrypt issuance + auto-renewal only)"
say ""
say " Everything else stays internal: Postgres/Redis are not published, and the"
say " app has no plain-HTTP listener (TLS terminates in the container)."
[ "${CERT_MODE:-$(read_env CERT_MODE)}" = "1" ] && say " Self-signed cert: your browser/SFTP client will warn until you trust it."
say ""
say " Re-run any time to pick up changes:  sudo ./setup-secure.sh"
say "   (reuses .env, rebuilds the image, recreates containers — data is kept)"
say ""
say " *** BACK UP ./.env OFF THIS VM NOW — it holds ENCRYPTION_KEY. ***"
say " Losing that key = every stored file (and any storage backup) is gone."
say "==================================================================="
