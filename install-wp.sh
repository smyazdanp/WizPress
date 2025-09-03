#!/usr/bin/env bash
# WordPress One-Click Installer (Hardened, Idempotent, Non-root deploy)
# Tested on Ubuntu 22.04 / 24.04
# Code comments in English (per user preference).

set -Eeuo pipefail
trap 'echo "[ERROR] Line $LINENO failed."; exit 1' ERR

# --- Helpers ---------------------------------------------------------------

log() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
error_exit() { echo "[ERROR] $*" >&2; exit 1; }

require_root() {
  [[ $EUID -ne 0 ]] && error_exit "Run this script as root."
}

get_input_with_default() {
  # Prompt with default; if ENV already set or non-interactive, use that
  local prompt_text="$1" default_value="$2" varname="$3"
  local current="${!varname:-}"
  if [[ -n "$current" ]]; then
    export "$varname=$current"
    return
  fi
  if [ -t 0 ]; then
    read -rp "$prompt_text (default: $default_value): " user_input || true
    if [[ -z "$user_input" ]]; then export "$varname=$default_value"; else export "$varname=$user_input"; fi
  else
    export "$varname=$default_value"
  fi
}

get_secret_with_confirm() {
  # Hidden password prompt with confirmation, or use ENV if provided
  local prompt_text="$1" varname="$2" envval="${!varname:-}"
  if [[ -n "$envval" ]]; then
    export "$varname=$envval"
    return
  fi
  local p1 p2
  while true; do
    read -srp "$prompt_text: " p1; echo
    read -srp "Confirm password: " p2; echo
    if [[ -z "$p1" ]]; then
      echo "Password cannot be empty."
      continue
    fi
    if [[ "$p1" != "$p2" ]]; then
      echo "Passwords do not match. Try again."
      continue
    fi
    if (( ${#p1} < 8 )); then
      echo "Password must be at least 8 characters."
      continue
    fi
    export "$varname=$p1"
    break
  done
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || \
    error_exit "Invalid port: $port (must be 1..65535)."
}

validate_domain() {
  local domain="$1"
  [[ -n "$domain" ]] || error_exit "Domain cannot be empty."
  [[ "$domain" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || \
    error_exit "Invalid domain format: $domain"
}

validate_username() {
  local u="$1"
  [[ "$u" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || error_exit "Invalid username: $u"
}

check_port_free() {
  local port="$1"
  if ss -tulpn 2>/dev/null | grep -qE "LISTEN.*[:.]$port[[:space:]]"; then
    warn "Port $port seems in use. We'll try to continue, but Nginx may fail to bind."
  fi
}

randpass() { openssl rand -base64 16 | tr -d '\n'; }

php_version() { php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' ; }

slugify_db() {
  # Alnum + underscore for DB identifiers
  local s
  s="$(echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/_/g;s/^_+|_+$//g')"
  echo "${s:0:16}"
}

ensure_cmd() { command -v "$1" >/dev/null 2>&1 || error_exit "Missing command: $1"; }

# --- Pre-checks & Inputs ---------------------------------------------------

require_root() {
  # POSIX-safe: works in sh/bash; no [[ ]] and no $EUID dependency
  if [ "$(id -u)" -ne 0 ]; then
    error_exit "Run this script as root."
  fi
}

get_input_with_default "Enter your domain name (e.g., example.com)" "yourdomain.com" DOMAIN_NAME
validate_domain "$DOMAIN_NAME"

# Detect current SSH port (fallback 22)
DETECTED_SSH_PORT="$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -n1 || true)"
DETECTED_SSH_PORT="${DETECTED_SSH_PORT:-22}"
get_input_with_default "SSH port" "$DETECTED_SSH_PORT" SSH_PORT
validate_port "$SSH_PORT"

# Recommended to keep 443 for best UX/ACME; script supports custom port for serving
get_input_with_default "HTTPS serve port (keep 443 unless necessary)" "443" HTTPS_PORT
validate_port "$HTTPS_PORT"

# WordPress settings
get_input_with_default "WordPress locale" "fa_IR" WP_LOCALE
get_input_with_default "Site Title" "My WordPress Site" WP_TITLE
get_input_with_default "Admin Username" "admin" WP_ADMIN_USER
get_input_with_default "Admin Email" "admin@$DOMAIN_NAME" WP_ADMIN_EMAIL

# Deploy user (non-root) who will own the site files
get_input_with_default "Deploy username" "WP-U-New" WP_DEPLOY_USER
validate_username "$WP_DEPLOY_USER"
get_secret_with_confirm "Set password for $WP_DEPLOY_USER" WP_DEPLOY_PASS

# Derived paths and versions
WEB_ROOT="/var/www/$DOMAIN_NAME"
PUBLIC_DIR="$WEB_ROOT/public"
NGINX_SITE="/etc/nginx/sites-available/$DOMAIN_NAME.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN_NAME.conf"
PHPV="$(php_version || true || echo '8.2')"

check_port_free 80
check_port_free 443

# --- System update & packages ---------------------------------------------

log "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y

log "Installing required packages..."
apt install -y \
  nginx mariadb-server mariadb-client \
  php-fpm php-mysql php-cli php-json php-common php-zip php-gd php-mbstring php-curl php-xml php-bcmath php-soap php-intl \
  unzip curl wget dnsutils \
  certbot python3-certbot-nginx

# Install WP-CLI (phar)
if ! command -v wp >/dev/null 2>&1; then
  log "Installing WP-CLI..."
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
  chmod +x /usr/local/bin/wp
fi

# Enable and start services
systemctl enable --now nginx
systemctl enable --now mariadb
systemctl enable --now "php$PHPV-fpm" || true

# --- Firewall (UFW) -------------------------------------------------------

log "Configuring UFW..."
ufw allow "OpenSSH" >/dev/null 2>&1 || true
if [[ "$SSH_PORT" != "22" ]]; then ufw allow "$SSH_PORT"/tcp || true; fi
ufw allow 80/tcp || true
ufw allow 443/tcp || true
if [[ "$HTTPS_PORT" != "443" ]]; then ufw allow "$HTTPS_PORT"/tcp || true; fi
ufw --force enable

# --- Create deploy user (non-root) ----------------------------------------

log "Creating deploy user: $WP_DEPLOY_USER ..."
if ! id -u "$WP_DEPLOY_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$WP_DEPLOY_USER"
  echo "$WP_DEPLOY_USER:$WP_DEPLOY_PASS" | chpasswd
  mkdir -p "/home/$WP_DEPLOY_USER/.ssh"
  chmod 700 "/home/$WP_DEPLOY_USER/.ssh"
  touch "/home/$WP_DEPLOY_USER/.ssh/authorized_keys"
  chmod 600 "/home/$WP_DEPLOY_USER/.ssh/authorized_keys"
  chown -R "$WP_DEPLOY_USER:$WP_DEPLOY_USER" "/home/$WP_DEPLOY_USER/.ssh"
else
  echo "$WP_DEPLOY_USER:$WP_DEPLOY_PASS" | chpasswd
fi

# --- Web root & permissions -----------------------------------------------

log "Preparing web root structure..."
mkdir -p "$PUBLIC_DIR"
# Owner: deploy user; Group: www-data so PHP can write
chown -R "$WP_DEPLOY_USER:www-data" "$WEB_ROOT"
# Directories group-writable + setgid; files group-writable
find "$WEB_ROOT" -type d -exec chmod 2775 {} \;
find "$WEB_ROOT" -type f -exec chmod 0664 {} \;

# --- Nginx base config (HTTP only for ACME) -------------------------------

log "Configuring Nginx for ACME on :80..."
rm -f /etc/nginx/sites-enabled/default

cat > "$NGINX_SITE" <<'EOF'
# Managed by WP One-Click Installer (HTTP-only for ACME)

server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_REPLACE www.DOMAIN_REPLACE;

    root /var/www/DOMAIN_REPLACE/public;
    index index.php index.html;

    # ACME challenge
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/DOMAIN_REPLACE/public;
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/phpPHPV_REPLACE-fpm.sock;
    }

    # Block hidden files except .well-known
    location ~ /\.(?!well-known).* { deny all; }
}
EOF

sed -ri "s/DOMAIN_REPLACE/$DOMAIN_NAME/g" "$NGINX_SITE"
sed -ri "s/PHPV_REPLACE/$PHPV/g" "$NGINX_SITE"

ln -sf "$NGINX_SITE" "$NGINX_LINK"
nginx -t
systemctl reload nginx

# --- Optional DNS check (warning only) ------------------------------------

log "Checking DNS (non-strict)..."
SERVER_IP="$(curl -fsSL https://ipinfo.io/ip || true)"
RESOLVED_IP="$(dig +short A "$DOMAIN_NAME" | head -n1 || true)"
if [[ -n "$SERVER_IP" && -n "$RESOLVED_IP" && "$SERVER_IP" != "$RESOLVED_IP" ]]; then
  warn "DNS for $DOMAIN_NAME resolves to $RESOLVED_IP but server public IP is $SERVER_IP. If behind Cloudflare proxy, this is expected."
fi

# --- MariaDB hardening & DB creation --------------------------------------

log "Hardening MariaDB (minimal) and creating DB..."
mysql -e "DELETE FROM mysql.user WHERE User='';" || true
mysql -e "DROP DATABASE IF EXISTS test;" || true
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || true
mysql -e "FLUSH PRIVILEGES;" || true

DB_NAME="$(slugify_db "${DOMAIN_NAME%.*}")_wp"
DB_USER="$(slugify_db "${DOMAIN_NAME%%.*}")_u"
DB_PASS="$(randpass)"

mysql -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
mysql -e "GRANT ALL ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# --- WordPress download & config (run as deploy user) ---------------------

log "Downloading WordPress via WP-CLI as $WP_DEPLOY_USER ..."
sudo -u "$WP_DEPLOY_USER" wp core download \
  --path="$PUBLIC_DIR" \
  --locale="$WP_LOCALE" \
  --force

log "Creating wp-config.php (WP-CLI)..."
sudo -u "$WP_DEPLOY_USER" wp config create \
  --path="$PUBLIC_DIR" \
  --dbname="$DB_NAME" \
  --dbuser="$DB_USER" \
  --dbpass="$DB_PASS" \
  --dbhost="localhost" \
  --dbprefix="wp_" \
  --skip-check --force

# Useful constants
sudo -u "$WP_DEPLOY_USER" wp config set WP_MEMORY_LIMIT "256M" --path="$PUBLIC_DIR"
sudo -u "$WP_DEPLOY_USER" wp config set WP_MAX_MEMORY_LIMIT "512M" --path="$PUBLIC_DIR"
sudo -u "$WP_DEPLOY_USER" wp config set FS_METHOD "direct" --path="$PUBLIC_DIR"
sudo -u "$WP_DEPLOY_USER" wp config set DISALLOW_FILE_EDIT "true" --path="$PUBLIC_DIR"
sudo -u "$WP_DEPLOY_USER" wp config shuffle-salts --path="$PUBLIC_DIR"

# Ensure final ownership/permissions (deploy:www-data; group-writable)
chown -R "$WP_DEPLOY_USER:www-data" "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 2775 {} \;
find "$WEB_ROOT" -type f -exec chmod 0664 {} \;

# --- Issue TLS certificate (Let's Encrypt) --------------------------------

log "Requesting Let's Encrypt certificate..."
certbot certonly --nginx \
  -d "$DOMAIN_NAME" -d "www.$DOMAIN_NAME" \
  --agree-tos --email "admin@$DOMAIN_NAME" \
  --non-interactive --redirect || error_exit "Certbot failed."

# --- Nginx HTTPS vhost + redirect from 80 ---------------------------------

log "Writing final Nginx HTTPS vhost..."
cat > "$NGINX_SITE" <<'EOF'
# Managed by WP One-Click Installer (HTTPS)

# login rate-limit and global server_tokens off
# defined in /etc/nginx/conf.d/limit_req.conf

server {
    listen HTTPS_PORT_REPLACE ssl http2;
    listen [::]:HTTPS_PORT_REPLACE ssl http2;
    server_name DOMAIN_REPLACE www.DOMAIN_REPLACE;

    root /var/www/DOMAIN_REPLACE/public;
    index index.php index.html;

    # TLS
    ssl_certificate     /etc/letsencrypt/live/DOMAIN_REPLACE/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/DOMAIN_REPLACE/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 64M;
    server_tokens off;

    # Block sensitive files
    location ~* /(?:readme|license)\.(?:txt|html)$ { deny all; }
    location = /xmlrpc.php { deny all; }
    location ~ /\.(?!well-known).* { deny all; }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    # Login brute-force mitigation
    location = /wp-login.php {
        limit_req zone=login burst=5 nodelay;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/phpPHPV_REPLACE-fpm.sock;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/phpPHPV_REPLACE-fpm.sock;
    }
}

# HTTP -> HTTPS redirect (custom port aware)
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_REPLACE www.DOMAIN_REPLACE;
    return 301 https://$host:HTTPS_PORT_REPLACE$request_uri;
}
EOF

sed -ri "s/DOMAIN_REPLACE/$DOMAIN_NAME/g" "$NGINX_SITE"
sed -ri "s/PHPV_REPLACE/$PHPV/g" "$NGINX_SITE"
sed -ri "s/HTTPS_PORT_REPLACE/$HTTPS_PORT/g" "$NGINX_SITE"

mkdir -p /etc/nginx/conf.d
if ! grep -qs 'zone=login' /etc/nginx/conf.d/limit_req.conf 2>/dev/null; then
  cat > /etc/nginx/conf.d/limit_req.conf <<'EOF'
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
server_tokens off;
EOF
fi

nginx -t
systemctl reload nginx

# --- PHP tuning ------------------------------------------------------------

log "Tuning PHP-FPM..."
PHP_INI="/etc/php/$PHPV/fpm/php.ini"
sed -ri 's/^memory_limit\s*=.*/memory_limit = 256M/' "$PHP_INI"
sed -ri 's/^upload_max_filesize\s*=.*/upload_max_filesize = 64M/' "$PHP_INI"
sed -ri 's/^post_max_size\s*=.*/post_max_size = 64M/' "$PHP_INI"
systemctl restart "php$PHPV-fpm"

# --- WordPress core install & permalinks ----------------------------------

log "Installing WordPress core..."
WP_URL="https://$DOMAIN_NAME"
if [[ "$HTTPS_PORT" != "443" ]]; then WP_URL="https://$DOMAIN_NAME:$HTTPS_PORT"; fi

WP_ADMIN_PASS="$(randpass)"

sudo -u "$WP_DEPLOY_USER" wp core install \
  --path="$PUBLIC_DIR" \
  --url="$WP_URL" \
  --title="$WP_TITLE" \
  --admin_user="$WP_ADMIN_USER" \
  --admin_password="$WP_ADMIN_PASS" \
  --admin_email="$WP_ADMIN_EMAIL"

sudo -u "$WP_DEPLOY_USER" wp rewrite structure '/%postname%/' --path="$PUBLIC_DIR"
sudo -u "$WP_DEPLOY_USER" wp rewrite flush --hard --path="$PUBLIC_DIR"

# Ensure permissions again (in case WP-CLI wrote files)
chown -R "$WP_DEPLOY_USER:www-data" "$WEB_ROOT"
find "$WEB_ROOT" -type d -exec chmod 2775 {} \;
find "$WEB_ROOT" -type f -exec chmod 0664 {} \;

# --- Credentials output ----------------------------------------------------

log "Saving credentials securely..."
umask 077
CREDS="/root/wp-$DOMAIN_NAME-$(date +%F).credentials"
{
  echo "================= WordPress Deployment ==================="
  echo "Domain      : $DOMAIN_NAME"
  echo "URL         : $WP_URL"
  echo "----------------------------------------------------------"
  echo "Admin User  : $WP_ADMIN_USER"
  echo "Admin Pass  : $WP_ADMIN_PASS"
  echo "Admin Email : $WP_ADMIN_EMAIL"
  echo "----------------------------------------------------------"
  echo "DB Name     : $DB_NAME"
  echo "DB User     : $DB_USER"
  echo "DB Pass     : $DB_PASS"
  echo "----------------------------------------------------------"
  echo "Deploy User : $WP_DEPLOY_USER"
  echo "Deploy Pass : (set by you at install time)"
  echo "Home Dir    : /home/$WP_DEPLOY_USER"
  echo "=========================================================="
} > "$CREDS"

log "Installation completed!"
log "Dashboard : $WP_URL/wp-admin"
log "Credentials stored at: $CREDS"

# Note: Certbot installs a systemd timer for auto-renewal by default.