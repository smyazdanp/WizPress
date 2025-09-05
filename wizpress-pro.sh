#!/usr/bin/env bash
# WizPress Pro - One-shot WordPress installer for Ubuntu (Nginx + PHP-FPM + MariaDB + SSL + UFW)
# Author: ChatGPT (rewritten for robustness)
# License: MIT
#
# Notes:
# - Tested logically for Ubuntu 20.04/22.04/24.04. Designed to be idempotent where possible.
# - Code comments are in English (per user's preference).
# - Runs as root. Creates a non-root owner user for the site files (default: wpunew).
# - Handles typical pitfalls (CRLF issues, missing wp-cli, UFW interactive prompt, PHP memory limits, FPM socket auto-detect).

set -Eeuo pipefail

# ---------------------------
# Utility & Traps
# ---------------------------
err() {
  local exit_code=$?
  echo -e "\n[ERROR] Line ${BASH_LINENO[0]} failed. Aborting (exit ${exit_code})." 1>&2
  exit "$exit_code"
}
trap err ERR

log()   { echo "[INFO] $*"; }
warn()  { echo "[WARN] $*" >&2; }
die()   { echo "[FATAL] $*" >&2; exit 1; }
exists(){ command -v "$1" >/dev/null 2>&1; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "Please run as root (use: sudo bash $0)"
  fi
}

# ---------------------------
# Defaults (can be overridden by env)
# ---------------------------
APP_USER="${APP_USER:-wpunew}"           # Local system user to own WP files (no spaces/hyphens advised)
APP_GROUP="${APP_GROUP:-www-data}"       # Group for Nginx/PHP-FPM
SITE_ROOT_BASE="${SITE_ROOT_BASE:-/var/www}"

# PHP tuning
PHP_MEMORY_LIMIT="${PHP_MEMORY_LIMIT:-512M}"
PHP_UPLOAD_LIMIT="${PHP_UPLOAD_LIMIT:-64M}"
PHP_POST_MAX="${PHP_POST_MAX:-64M}"
PHP_MAX_EXEC="${PHP_MAX_EXEC:-120}"

# WP locale default
WP_LOCALE="${WP_LOCALE:-fa_IR}"

export DEBIAN_FRONTEND=noninteractive

# ---------------------------
# Prompt helpers
# ---------------------------
ask() {
  local prompt="$1" default="$2" varname="$3"
  local value
  if [[ -n "${!varname:-}" ]]; then
    # env preset takes precedence
    return 0
  fi
  read -rp "$prompt [default: ${default}]: " value || true
  if [[ -z "$value" ]]; then
    eval "$varname=\"${default}\""
  else
    eval "$varname=\"${value}\""
  fi
}

# Simple domain validator
validate_domain() {
  local domain="$1"
  [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

random_pw() {
  # Generates a fairly strong random password (no slashes to avoid escape issues)
  tr -dc 'A-Za-z0-9!@#%^+=_' </dev/urandom | head -c 24
}

detect_php_fpm_sock() {
  local sock
  sock="$(find /run/php -maxdepth 1 -type s -name 'php*-fpm.sock' 2>/dev/null | head -n1 || true)"
  echo "$sock"
}

detect_php_version() {
  php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;'
}

php_ini_paths() {
  local ver="$1"
  echo "/etc/php/${ver}/fpm/php.ini /etc/php/${ver}/cli/php.ini"
}

# ---------------------------
# Main
# ---------------------------
main() {
  require_root

  # 1) Collect inputs
  ask "Enter your domain (A record must point here)" "example.com" DOMAIN
  if ! validate_domain "$DOMAIN"; then
    die "Invalid domain: ${DOMAIN}"
  fi
  ask "Enter contact email (for SSL/Let's Encrypt)" "admin@${DOMAIN}" LE_EMAIL
  ask "WordPress locale" "${WP_LOCALE}" WP_LOCALE
  ask "Create/Use system user to own files" "${APP_USER}" APP_USER

  SITE_ROOT="${SITE_ROOT_BASE}/${DOMAIN}"
  WP_PATH="${SITE_ROOT}/public"
  DB_NAME=${DB_NAME:-"wp_$(echo "$DOMAIN" | tr '.' '_' )"}
  DB_USER=${DB_USER:-"wp_$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)"}
  DB_PASS=${DB_PASS:-"$(random_pw)"}
  ADMIN_USER=${ADMIN_USER:-"wpadmin"}
  ADMIN_PASS=${ADMIN_PASS:-"$(random_pw)"}
  ADMIN_EMAIL=${ADMIN_EMAIL:-"admin@${DOMAIN}"}

  log "Domain          : $DOMAIN"
  log "Site root       : $SITE_ROOT"
  log "WP path         : $WP_PATH"
  log "DB name         : $DB_NAME"
  log "DB user         : $DB_USER"
  log "Admin user      : $ADMIN_USER"
  log "LE email        : $LE_EMAIL"
  log "WP locale       : $WP_LOCALE"
  log "Owner user      : $APP_USER"
  sleep 1

  # 2) OS sanity
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu) : ;;
      *) warn "This script is tuned for Ubuntu. Detected: $ID";;
    esac
  fi

  # 3) Update & base packages
  log "Updating APT and installing base packages..."
  apt-get update -y
  apt-get install -y software-properties-common ca-certificates curl wget gnupg lsb-release \
                     unzip zip tar git jq ufw

  # 4) Nginx + MariaDB + PHP
  log "Installing Nginx, MariaDB, PHP-FPM, and common extensions..."
  apt-get install -y nginx mariadb-server

  # Let distro PHP be installed (stable); install extensions
  apt-get install -y php php-fpm php-mysql php-curl php-xml php-gd php-mbstring php-zip php-intl php-bcmath imagemagick php-imagick

  systemctl enable --now nginx
  systemctl enable --now mariadb

  # 5) Create web user (non-root owner)
  if id "$APP_USER" >/dev/null 2>&1; then
    log "User '${APP_USER}' already exists."
  else
    log "Creating user '${APP_USER}' (no shell login)..."
    adduser --disabled-password --gecos "" "$APP_USER"
  fi
  usermod -aG "${APP_GROUP}" "$APP_USER"

  # 6) Tune PHP limits
  PHP_VER="$(detect_php_version)"
  for ini in $(php_ini_paths "$PHP_VER"); do
    if [[ -f "$ini" ]]; then
      log "Tuning PHP ini at $ini"
      sed -ri "s~^memory_limit = .*~memory_limit = ${PHP_MEMORY_LIMIT}~" "$ini"
      sed -ri "s~^upload_max_filesize = .*~upload_max_filesize = ${PHP_UPLOAD_LIMIT}~" "$ini"
      sed -ri "s~^post_max_size = .*~post_max_size = ${PHP_POST_MAX}~" "$ini"
      sed -ri "s~^max_execution_time = .*~max_execution_time = ${PHP_MAX_EXEC}~" "$ini"
    fi
  done
  systemctl restart "php${PHP_VER}-fpm"

  # 7) Secure MariaDB (low-risk subset)
  log "Securing MariaDB (removing test DB & anonymous users)..."
  mysql -u root <<SQL
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL

  # 8) Create DB & user for WordPress
  log "Creating database and user for WordPress..."
  mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

  # 9) Setup directories
  log "Preparing web root at ${WP_PATH}..."
  mkdir -p "$WP_PATH"
  chown -R "$APP_USER:$APP_GROUP" "$SITE_ROOT"
  chmod -R 0750 "$SITE_ROOT"

  # 10) Nginx server block
  FPM_SOCK="$(detect_php_fpm_sock)"
  [[ -z "$FPM_SOCK" ]] && die "Could not detect PHP-FPM socket under /run/php"
  NGINX_SITES="/etc/nginx/sites-available"
  NGINX_ENABLED="/etc/nginx/sites-enabled"
  NCONF="${NGINX_SITES}/${DOMAIN}"

  log "Writing Nginx vhost to ${NCONF} (FPM: ${FPM_SOCK})"
  cat >"$NCONF" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    root ${WP_PATH};
    index index.php index.html index.htm;

    client_max_body_size ${PHP_UPLOAD_LIMIT};

    # Let’s Encrypt challenge (pre-SSL issuance)
    location ~* ^/.well-known/acme-challenge/ { allow all; }

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${FPM_SOCK};
        fastcgi_read_timeout 120s;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp)\$ {
        expires 30d;
        access_log off;
    }

    # Deny access to .ht* files
    location ~ /\.ht { deny all; }
}
NGINX

  # Enable site
  ln -sf "$NCONF" "${NGINX_ENABLED}/${DOMAIN}"
  # Disable default if present
  if [[ -f "${NGINX_ENABLED}/default" ]]; then
    rm -f "${NGINX_ENABLED}/default"
  fi
  nginx -t
  systemctl reload nginx

  # 11) Install WP-CLI if missing
  if ! exists wp; then
    log "Installing WP-CLI..."
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
    chmod +x /usr/local/bin/wp
  fi

  # 12) Download & configure WordPress
  log "Downloading WordPress (${WP_LOCALE})..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp core download --path="$WP_PATH" --locale="$WP_LOCALE" --force

  log "Creating wp-config.php..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config create \
      --path="$WP_PATH" \
      --dbname="$DB_NAME" --dbuser="$DB_USER" --dbpass="$DB_PASS" \
      --dbhost=localhost --dbprefix="wp_" --skip-check --force

  # Set unique salts
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config shuffle-salts --path="$WP_PATH"

  # 13) Issue SSL (attempt)
  log "Attempting Let's Encrypt SSL with certbot..."
  apt-get install -y certbot python3-certbot-nginx
  if certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" -m "$LE_EMAIL" --agree-tos --no-eff-email --redirect --non-interactive; then
    log "SSL installed successfully."
    SITE_URL="https://${DOMAIN}"
  else
    warn "Certbot failed (DNS not pointing or port 80 blocked). Keeping HTTP for now."
    SITE_URL="http://${DOMAIN}"
  fi

  # 14) Install WP core
  log "Running WordPress installation..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp core install \
      --path="$WP_PATH" \
      --url="$SITE_URL" \
      --title="$DOMAIN" \
      --admin_user="$ADMIN_USER" \
      --admin_password="$ADMIN_PASS" \
      --admin_email="$ADMIN_EMAIL" \
      --skip-email

  # 15) Harden permissions
  log "Hardening permissions..."
  find "$WP_PATH" -type d -exec chmod 0750 {} \;
  find "$WP_PATH" -type f -exec chmod 0640 {} \;
  chown -R "$APP_USER:$APP_GROUP" "$WP_PATH"
  # Let Nginx (www-data) write to standard upload dirs
  mkdir -p "$WP_PATH/wp-content/uploads"
  chgrp -R "$APP_GROUP" "$WP_PATH/wp-content"
  chmod -R g+w "$WP_PATH/wp-content"

  # 16) UFW firewall
  log "Configuring UFW..."
  ufw allow OpenSSH || true
  ufw allow 'Nginx Full' || true
  ufw --force enable || true

  # 17) Summary
  cat <<SUMMARY

============================================================
 WordPress is ready!
------------------------------------------------------------
 URL        : ${SITE_URL}
 Admin User : ${ADMIN_USER}
 Admin Pass : ${ADMIN_PASS}
 Admin Email: ${ADMIN_EMAIL}

 DB Name    : ${DB_NAME}
 DB User    : ${DB_USER}
 DB Pass    : ${DB_PASS}

 Path       : ${WP_PATH}
 Owner      : ${APP_USER}:${APP_GROUP}

 * Keep these credentials safe.
 * If SSL failed, ensure DNS points to this server and re-run:
     certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} -m ${LE_EMAIL} --agree-tos --no-eff-email --redirect --non-interactive

 Enjoy!
============================================================
SUMMARY
}

main "$@"
