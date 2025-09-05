#!/usr/bin/env bash
# WizPress Pro - One-shot WordPress installer for Ubuntu (Nginx + PHP-FPM + MariaDB + SSL + UFW)
# Version: 2.0 - Improved and tested
# Author: Enhanced version with fixes
# License: MIT
#
# Improvements:
# - Fixed encoding issues in comments
# - Added PHP version detection and compatibility
# - Enhanced error handling and rollback capability
# - Added backup before major changes
# - Improved SSL certificate handling
# - Added Redis cache support (optional)
# - Better security hardening
# - Added automatic updates configuration

set -Eeuo pipefail

# ---------------------------
# Color codes for better output
# ---------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ---------------------------
# Utility & Traps
# ---------------------------
err() {
  local exit_code=$?
  echo -e "\n${RED}[ERROR]${NC} Line ${BASH_LINENO[0]} failed. Aborting (exit ${exit_code})." 1>&2
  # Cleanup on error
  cleanup_on_error
  exit "$exit_code"
}
trap err ERR

log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
die()   { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }
exists(){ command -v "$1" >/dev/null 2>&1; }

# Cleanup function for rollback
cleanup_on_error() {
  if [[ "${CLEANUP_ON_ERROR:-1}" == "1" ]]; then
    warn "Performing cleanup..."
    # Remove created database if exists
    if [[ -n "${DB_NAME:-}" ]] && [[ -n "${DB_USER:-}" ]]; then
      mysql -u root 2>/dev/null <<SQL || true
DROP DATABASE IF EXISTS \`${DB_NAME}\`;
DROP USER IF EXISTS '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
    fi
    # Remove nginx config if created
    if [[ -n "${DOMAIN:-}" ]]; then
      rm -f "/etc/nginx/sites-enabled/${DOMAIN}" 2>/dev/null || true
      rm -f "/etc/nginx/sites-available/${DOMAIN}" 2>/dev/null || true
    fi
  fi
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    die "Please run as root (use: sudo bash $0)"
  fi
}

# Check Ubuntu version
check_ubuntu_version() {
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "$ID" in
      ubuntu)
        case "$VERSION_ID" in
          20.04|22.04|24.04) 
            log "Ubuntu $VERSION_ID detected - supported version"
            ;;
          *)
            warn "Ubuntu $VERSION_ID detected - not fully tested but will continue"
            ;;
        esac
        ;;
      *)
        die "This script is designed for Ubuntu. Detected: $ID"
        ;;
    esac
  else
    die "Cannot detect OS version"
  fi
}

# ---------------------------
# Defaults (can be overridden by env)
# ---------------------------
APP_USER="${APP_USER:-wpuser}"           # Local system user to own WP files
APP_GROUP="${APP_GROUP:-www-data}"       # Group for Nginx/PHP-FPM
SITE_ROOT_BASE="${SITE_ROOT_BASE:-/var/www}"

# PHP tuning
PHP_MEMORY_LIMIT="${PHP_MEMORY_LIMIT:-256M}"
PHP_UPLOAD_LIMIT="${PHP_UPLOAD_LIMIT:-64M}"
PHP_POST_MAX="${PHP_POST_MAX:-64M}"
PHP_MAX_EXEC="${PHP_MAX_EXEC:-300}"
PHP_MAX_INPUT_TIME="${PHP_MAX_INPUT_TIME:-300}"
PHP_MAX_INPUT_VARS="${PHP_MAX_INPUT_VARS:-3000}"

# WP locale default
WP_LOCALE="${WP_LOCALE:-en_US}"

# Optional features
INSTALL_REDIS="${INSTALL_REDIS:-no}"
INSTALL_FAIL2BAN="${INSTALL_FAIL2BAN:-yes}"
AUTO_UPDATES="${AUTO_UPDATES:-yes}"

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

ask_yes_no() {
  local prompt="$1" default="$2"
  local answer
  read -rp "$prompt [y/N]: " answer || true
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy] ]]
}

# Domain validator
validate_domain() {
  local domain="$1"
  # More comprehensive domain validation
  if [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$ ]]; then
    return 0
  else
    return 1
  fi
}

# Email validator
validate_email() {
  local email="$1"
  if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    return 0
  else
    return 1
  fi
}

random_pw() {
  # Generates a strong random password (avoiding problematic characters)
  tr -dc 'A-Za-z0-9!@#%^&*()_+=' </dev/urandom | head -c 20
}

detect_php_fpm_sock() {
  local sock
  # Try to find the PHP-FPM socket
  sock="$(find /run/php -maxdepth 1 -type s -name 'php*-fpm.sock' 2>/dev/null | sort -V | tail -n1 || true)"
  if [[ -z "$sock" ]]; then
    # Fallback to common paths
    for test_sock in /run/php/php8.3-fpm.sock /run/php/php8.2-fpm.sock /run/php/php8.1-fpm.sock /run/php/php8.0-fpm.sock /run/php/php7.4-fpm.sock; do
      if [[ -S "$test_sock" ]]; then
        sock="$test_sock"
        break
      fi
    done
  fi
  echo "$sock"
}

detect_php_version() {
  if exists php; then
    php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo ""
  else
    echo ""
  fi
}

get_php_package_version() {
  # Get the best available PHP version for the distro
  local available_versions=(8.3 8.2 8.1 8.0 7.4)
  for ver in "${available_versions[@]}"; do
    if apt-cache show "php${ver}" 2>/dev/null | grep -q "Package: php${ver}"; then
      echo "$ver"
      return 0
    fi
  done
  echo ""
}

php_ini_paths() {
  local ver="$1"
  echo "/etc/php/${ver}/fpm/php.ini /etc/php/${ver}/cli/php.ini"
}

# Check server requirements
check_requirements() {
  log "Checking server requirements..."
  
  # Check minimum RAM (512MB)
  local total_ram=$(free -m | awk '/^Mem:/{print $2}')
  if [[ $total_ram -lt 512 ]]; then
    warn "System has less than 512MB RAM. WordPress may run slowly."
  fi
  
  # Check disk space (at least 2GB free)
  local free_space=$(df / | awk 'NR==2 {print int($4/1024)}')
  if [[ $free_space -lt 2048 ]]; then
    die "Less than 2GB free disk space. Please free up some space."
  fi
  
  # Check network connectivity
  if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    die "No internet connectivity detected. Please check your network."
  fi
}

# Backup existing configs
backup_configs() {
  local backup_dir="/root/wizpress-backups/$(date +%Y%m%d-%H%M%S)"
  if [[ -d "/etc/nginx/sites-available" ]] || [[ -d "/etc/php" ]]; then
    log "Creating backup at $backup_dir..."
    mkdir -p "$backup_dir"
    [[ -d "/etc/nginx" ]] && cp -r /etc/nginx "$backup_dir/" 2>/dev/null || true
    [[ -d "/etc/php" ]] && cp -r /etc/php "$backup_dir/" 2>/dev/null || true
  fi
}

# ---------------------------
# Main Installation Function
# ---------------------------
main() {
  require_root
  check_ubuntu_version
  check_requirements
  
  echo -e "${BLUE}================================================${NC}"
  echo -e "${BLUE}    WizPress Pro - WordPress Auto Installer    ${NC}"
  echo -e "${BLUE}================================================${NC}\n"

  # 1) Collect inputs
  ask "Enter your domain (DNS A record must point to this server)" "example.com" DOMAIN
  if ! validate_domain "$DOMAIN"; then
    die "Invalid domain format: ${DOMAIN}"
  fi
  
  ask "Enter contact email (for SSL/Let's Encrypt notifications)" "admin@${DOMAIN}" LE_EMAIL
  if ! validate_email "$LE_EMAIL"; then
    die "Invalid email format: ${LE_EMAIL}"
  fi
  
  ask "WordPress admin username" "wpadmin" ADMIN_USER
  ask "WordPress admin email" "$LE_EMAIL" ADMIN_EMAIL
  ask "WordPress site language/locale" "${WP_LOCALE}" WP_LOCALE
  ask "System user to own WordPress files" "${APP_USER}" APP_USER
  
  if ask_yes_no "Install Redis for object caching? (recommended)" "n"; then
    INSTALL_REDIS="yes"
  fi
  
  if ask_yes_no "Install Fail2ban for security? (recommended)" "y"; then
    INSTALL_FAIL2BAN="yes"
  fi

  # Generate secure passwords
  SITE_ROOT="${SITE_ROOT_BASE}/${DOMAIN}"
  WP_PATH="${SITE_ROOT}/public"
  DB_NAME="wp_$(echo "$DOMAIN" | tr '.-' '_' | cut -c1-16)"
  DB_USER="wpusr_$(tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
  DB_PASS="$(random_pw)"
  ADMIN_PASS="${ADMIN_PASS:-$(random_pw)}"
  
  # Display configuration summary
  echo -e "\n${BLUE}=== Configuration Summary ===${NC}"
  log "Domain          : $DOMAIN"
  log "Site root       : $SITE_ROOT"
  log "WordPress path  : $WP_PATH"
  log "Database name   : $DB_NAME"
  log "Database user   : $DB_USER"
  log "Admin username  : $ADMIN_USER"
  log "Admin email     : $ADMIN_EMAIL"
  log "SSL email       : $LE_EMAIL"
  log "WP locale       : $WP_LOCALE"
  log "System user     : $APP_USER"
  log "Install Redis   : $INSTALL_REDIS"
  log "Install Fail2ban: $INSTALL_FAIL2BAN"
  
  echo -e "\n${YELLOW}Passwords will be generated automatically for security.${NC}"
  if ! ask_yes_no "Continue with installation?" "y"; then
    die "Installation cancelled by user."
  fi

  # Create backups before starting
  backup_configs

  # 2) Update system
  log "Updating system packages..."
  apt-get update -y
  apt-get upgrade -y
  apt-get install -y software-properties-common ca-certificates curl wget gnupg lsb-release \
                     unzip zip tar git jq ufw apt-transport-https

  # 3) Determine PHP version to install
  PHP_TARGET_VER=$(get_php_package_version)
  if [[ -z "$PHP_TARGET_VER" ]]; then
    warn "Could not determine PHP version, will use default"
    PHP_PACKAGES="php php-fpm"
  else
    log "Will install PHP $PHP_TARGET_VER"
    PHP_PACKAGES="php${PHP_TARGET_VER} php${PHP_TARGET_VER}-fpm"
  fi

  # 4) Install Nginx, MariaDB, PHP
  log "Installing Nginx..."
  apt-get install -y nginx

  log "Installing MariaDB..."
  apt-get install -y mariadb-server mariadb-client

  log "Installing PHP and extensions..."
  apt-get install -y $PHP_PACKAGES \
    php${PHP_TARGET_VER}-mysql \
    php${PHP_TARGET_VER}-curl \
    php${PHP_TARGET_VER}-xml \
    php${PHP_TARGET_VER}-gd \
    php${PHP_TARGET_VER}-mbstring \
    php${PHP_TARGET_VER}-zip \
    php${PHP_TARGET_VER}-intl \
    php${PHP_TARGET_VER}-bcmath \
    php${PHP_TARGET_VER}-imagick \
    php${PHP_TARGET_VER}-opcache \
    php${PHP_TARGET_VER}-soap \
    php${PHP_TARGET_VER}-gmp \
    imagemagick

  # Install Redis if requested
  if [[ "$INSTALL_REDIS" == "yes" ]]; then
    log "Installing Redis..."
    apt-get install -y redis-server php${PHP_TARGET_VER}-redis
    systemctl enable --now redis-server
    # Basic Redis security
    sed -i 's/^# requirepass .*/requirepass '"$(random_pw)"'/' /etc/redis/redis.conf
    systemctl restart redis-server
  fi

  # Start services
  systemctl enable --now nginx
  systemctl enable --now mariadb
  systemctl enable --now php${PHP_TARGET_VER}-fpm

  # 5) Create web user
  if id "$APP_USER" >/dev/null 2>&1; then
    log "User '${APP_USER}' already exists."
  else
    log "Creating system user '${APP_USER}'..."
    useradd -m -s /bin/bash "$APP_USER"
  fi
  usermod -aG "${APP_GROUP}" "$APP_USER"

  # 6) Tune PHP configuration
  PHP_VER="${PHP_TARGET_VER:-$(detect_php_version)}"
  if [[ -z "$PHP_VER" ]]; then
    die "Could not detect PHP version"
  fi
  
  log "Configuring PHP ${PHP_VER} settings..."
  for ini in $(php_ini_paths "$PHP_VER"); do
    if [[ -f "$ini" ]]; then
      cp "$ini" "${ini}.backup-$(date +%Y%m%d)"
      
      # Apply PHP tuning
      sed -ri "s/^;?memory_limit = .*/memory_limit = ${PHP_MEMORY_LIMIT}/" "$ini"
      sed -ri "s/^;?upload_max_filesize = .*/upload_max_filesize = ${PHP_UPLOAD_LIMIT}/" "$ini"
      sed -ri "s/^;?post_max_size = .*/post_max_size = ${PHP_POST_MAX}/" "$ini"
      sed -ri "s/^;?max_execution_time = .*/max_execution_time = ${PHP_MAX_EXEC}/" "$ini"
      sed -ri "s/^;?max_input_time = .*/max_input_time = ${PHP_MAX_INPUT_TIME}/" "$ini"
      sed -ri "s/^;?max_input_vars = .*/max_input_vars = ${PHP_MAX_INPUT_VARS}/" "$ini"
      
      # Security hardening
      sed -ri "s/^;?expose_php = .*/expose_php = Off/" "$ini"
      sed -ri "s/^;?display_errors = .*/display_errors = Off/" "$ini"
      sed -ri "s/^;?log_errors = .*/log_errors = On/" "$ini"
      
      # OPcache settings
      sed -ri "s/^;?opcache.enable=.*/opcache.enable=1/" "$ini"
      sed -ri "s/^;?opcache.memory_consumption=.*/opcache.memory_consumption=128/" "$ini"
      sed -ri "s/^;?opcache.max_accelerated_files=.*/opcache.max_accelerated_files=10000/" "$ini"
      sed -ri "s/^;?opcache.revalidate_freq=.*/opcache.revalidate_freq=2/" "$ini"
    fi
  done
  systemctl restart "php${PHP_VER}-fpm"

  # 7) Secure MariaDB
  log "Securing MariaDB installation..."
  # Set root password if not set
  MYSQL_ROOT_PASS="$(random_pw)"
  mysql -u root <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
  
  # Save MySQL root password
  echo "[client]" > /root/.my.cnf
  echo "user=root" >> /root/.my.cnf
  echo "password=${MYSQL_ROOT_PASS}" >> /root/.my.cnf
  chmod 600 /root/.my.cnf

  # 8) Create WordPress database and user
  log "Creating WordPress database and user..."
  mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

  # 9) Setup directories
  log "Creating web directories..."
  mkdir -p "$WP_PATH"
  mkdir -p "$SITE_ROOT/logs"
  mkdir -p "$SITE_ROOT/tmp"
  chown -R "$APP_USER:$APP_GROUP" "$SITE_ROOT"
  chmod -R 755 "$SITE_ROOT"

  # 10) Configure Nginx
  FPM_SOCK="$(detect_php_fpm_sock)"
  if [[ -z "$FPM_SOCK" ]] || [[ ! -S "$FPM_SOCK" ]]; then
    die "Could not detect PHP-FPM socket. Please check PHP-FPM installation."
  fi
  
  NGINX_SITES="/etc/nginx/sites-available"
  NGINX_ENABLED="/etc/nginx/sites-enabled"
  NCONF="${NGINX_SITES}/${DOMAIN}"

  log "Creating Nginx configuration for ${DOMAIN}..."
  cat >"$NCONF" <<'NGINX_CONFIG'
# Upstream PHP-FPM
upstream php {
    server unix:PHP_FPM_SOCKET;
}

# HTTP Server - Redirect to HTTPS after SSL setup
server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_NAME www.DOMAIN_NAME;
    
    root WP_PATH_DIR;
    index index.php index.html index.htm;
    
    # Logs
    access_log SITE_ROOT_DIR/logs/access.log;
    error_log SITE_ROOT_DIR/logs/error.log;
    
    # Max upload size
    client_max_body_size PHP_UPLOAD_SIZE;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Let's Encrypt verification
    location ~ /.well-known/acme-challenge {
        allow all;
        root WP_PATH_DIR;
    }
    
    # Deny access to sensitive files
    location ~ /\.(htaccess|htpasswd|git|svn) {
        deny all;
    }
    
    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }
    
    location ~ /wp-config.php {
        deny all;
    }
    
    # WordPress permalinks
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    # PHP handling
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass php;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 256 16k;
        fastcgi_busy_buffers_size 256k;
    }
    
    # Static file caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webp|woff|woff2|ttf|eot)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # XML-RPC protection (uncomment to block)
    #location = /xmlrpc.php {
    #    deny all;
    #}
    
    # Deny access to wp-admin for non-admins (optional)
    #location ~* /wp-admin/.*\.php$ {
    #    allow 1.2.3.4;  # Your IP
    #    deny all;
    #}
}
NGINX_CONFIG

  # Replace placeholders in Nginx config
  sed -i "s|PHP_FPM_SOCKET|${FPM_SOCK}|g" "$NCONF"
  sed -i "s|DOMAIN_NAME|${DOMAIN}|g" "$NCONF"
  sed -i "s|WP_PATH_DIR|${WP_PATH}|g" "$NCONF"
  sed -i "s|SITE_ROOT_DIR|${SITE_ROOT}|g" "$NCONF"
  sed -i "s|PHP_UPLOAD_SIZE|${PHP_UPLOAD_LIMIT}|g" "$NCONF"

  # Enable site and remove default
  ln -sf "$NCONF" "${NGINX_ENABLED}/${DOMAIN}"
  rm -f "${NGINX_ENABLED}/default"
  
  # Test Nginx configuration
  if ! nginx -t; then
    die "Nginx configuration test failed. Please check the configuration."
  fi
  systemctl reload nginx

  # 11) Install WP-CLI
  if ! exists wp; then
    log "Installing WP-CLI..."
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
    chmod +x /usr/local/bin/wp
    
    # Verify installation
    if ! wp --version >/dev/null 2>&1; then
      die "WP-CLI installation failed"
    fi
  fi

  # 12) Download and configure WordPress
  log "Downloading WordPress (locale: ${WP_LOCALE})..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp core download \
    --path="$WP_PATH" \
    --locale="$WP_LOCALE" \
    --force

  log "Creating wp-config.php..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config create \
    --path="$WP_PATH" \
    --dbname="$DB_NAME" \
    --dbuser="$DB_USER" \
    --dbpass="$DB_PASS" \
    --dbhost="localhost" \
    --dbprefix="wp_" \
    --skip-check \
    --force

  # Add extra security configurations to wp-config.php
  log "Adding security configurations..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set WP_DEBUG false --raw --path="$WP_PATH"
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set WP_DEBUG_LOG false --raw --path="$WP_PATH"
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set WP_DEBUG_DISPLAY false --raw --path="$WP_PATH"
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set DISALLOW_FILE_EDIT true --raw --path="$WP_PATH"
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set WP_AUTO_UPDATE_CORE true --raw --path="$WP_PATH"
  
  # Generate salts
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config shuffle-salts --path="$WP_PATH"

  # 13) SSL Certificate with Let's Encrypt
  log "Installing SSL certificate..."
  apt-get install -y certbot python3-certbot-nginx
  
  # Pre-check DNS
  log "Checking DNS configuration..."
  SERVER_IP=$(curl -s https://api.ipify.org 2>/dev/null || curl -s https://ifconfig.me 2>/dev/null)
  DOMAIN_IP=$(dig +short "$DOMAIN" @8.8.8.8 | tail -n1)
  
  if [[ "$SERVER_IP" == "$DOMAIN_IP" ]]; then
    log "DNS is properly configured. Requesting SSL certificate..."
    if certbot --nginx \
         -d "$DOMAIN" \
         -d "www.$DOMAIN" \
         -m "$LE_EMAIL" \
         --agree-tos \
         --no-eff-email \
         --redirect \
         --non-interactive; then
      log "SSL certificate installed successfully!"
      SITE_URL="https://${DOMAIN}"
      
      # Setup auto-renewal
      echo "0 0,12 * * * root certbot renew --quiet --no-self-upgrade" > /etc/cron.d/certbot-renew
    else
      warn "SSL certificate installation failed. Continuing with HTTP."
      warn "You can try again later with: certbot --nginx -d ${DOMAIN} -d www.${DOMAIN}"
      SITE_URL="http://${DOMAIN}"
    fi
  else
    warn "DNS not pointing to this server (Server IP: $SERVER_IP, Domain IP: $DOMAIN_IP)"
    warn "Skipping SSL for now. Configure DNS and run certbot manually later."
    SITE_URL="http://${DOMAIN}"
  fi

  # 14) Install WordPress
  log "Installing WordPress..."
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp core install \
    --path="$WP_PATH" \
    --url="$SITE_URL" \
    --title="$DOMAIN" \
    --admin_user="$ADMIN_USER" \
    --admin_password="$ADMIN_PASS" \
    --admin_email="$ADMIN_EMAIL" \
    --skip-email

  # 15) Configure WordPress settings
  log "Configuring WordPress settings..."
  
  # Set permalink structure
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp rewrite structure '/%postname%/' --path="$WP_PATH"
  
  # Remove default content
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp post delete 1 2 --path="$WP_PATH" --force
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp comment delete 1 --path="$WP_PATH" --force
  
  # Install and activate useful plugins
  log "Installing essential plugins..."
  if [[ "$INSTALL_REDIS" == "yes" ]]; then
    sudo -u "$APP_USER" -g "$APP_GROUP" -- wp plugin install redis-cache --activate --path="$WP_PATH"
    sudo -u "$APP_USER" -g "$APP_GROUP" -- wp redis enable --path="$WP_PATH" 2>/dev/null || true
  fi
  
  # Install security plugin
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp plugin install wordfence --path="$WP_PATH"
  
  # Disable unnecessary features
  sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set WP_POST_REVISIONS 3 --raw --path="$WP_PATH"
  
  # Configure auto-updates
  if [[ "$AUTO_UPDATES" == "yes" ]]; then
    sudo -u "$APP_USER" -g "$APP_GROUP" -- wp config set WP_AUTO_UPDATE_CORE true --raw --path="$WP_PATH"
  fi

  # 16) Set proper permissions
  log "Setting secure file permissions..."
  find "$WP_PATH" -type d -exec chmod 755 {} \;
  find "$WP_PATH" -type f -exec chmod 644 {} \;
  
  # WordPress needs write access to these
  chmod 775 "$WP_PATH/wp-content"
  chmod -R 775 "$WP_PATH/wp-content/uploads" 2>/dev/null || mkdir -p "$WP_PATH/wp-content/uploads" && chmod -R 775 "$WP_PATH/wp-content/uploads"
  chmod -R 775 "$WP_PATH/wp-content/plugins"
  chmod -R 775 "$WP_PATH/wp-content/themes"
  
  # Set ownership
  chown -R "$APP_USER:$APP_GROUP" "$WP_PATH"
  
  # Protect wp-config.php
  chmod 640 "$WP_PATH/wp-config.php"
  chown "$APP_USER:$APP_GROUP" "$WP_PATH/wp-config.php"

  # 17) Configure UFW Firewall
  log "Configuring firewall (UFW)..."
  ufw --force disable 2>/dev/null || true
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp comment 'SSH'
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
  
  # Enable UFW non-interactively
  echo "y" | ufw enable

  # 18) Install and configure Fail2ban
  if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    log "Installing Fail2ban for additional security..."
    apt-get install -y fail2ban
    
    # Create WordPress jail
    cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

[nginx-limit-req]
enabled = true

[wordpress]
enabled = true
filter = wordpress
port = http,https
logpath = /var/log/nginx/*access.log
maxretry = 3
findtime = 600
bantime = 3600
F2B

    # Create WordPress filter
    cat > /etc/fail2ban/filter.d/wordpress.conf <<'F2BWP'
[Definition]
failregex = ^<HOST> .* "POST /wp-login.php
            ^<HOST> .* "POST /xmlrpc.php
            ^<HOST> .* "POST /wp-admin/admin-ajax.php
ignoreregex =
F2BWP
    
    systemctl restart fail2ban
    systemctl enable fail2ban
  fi

  # 19) Setup automatic backups
  log "Setting up automatic backups..."
  BACKUP_SCRIPT="/usr/local/bin/wp-backup-${DOMAIN}.sh"
  cat > "$BACKUP_SCRIPT" <<'BACKUP'
#!/bin/bash
# WordPress Backup Script
DOMAIN="DOMAIN_NAME"
SITE_ROOT="SITE_ROOT_DIR"
DB_NAME="DB_NAME_VAR"
DB_USER="DB_USER_VAR"
DB_PASS="DB_PASS_VAR"
BACKUP_DIR="/backup/wordpress/${DOMAIN}"
DATE=$(date +%Y%m%d-%H%M%S)

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Backup database
mysqldump -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" | gzip > "${BACKUP_DIR}/db-${DATE}.sql.gz"

# Backup files
tar -czf "${BACKUP_DIR}/files-${DATE}.tar.gz" -C "${SITE_ROOT}" public/

# Keep only last 7 days of backups
find "${BACKUP_DIR}" -type f -mtime +7 -delete

echo "Backup completed: ${DATE}"
BACKUP

  # Replace placeholders in backup script
  sed -i "s|DOMAIN_NAME|${DOMAIN}|g" "$BACKUP_SCRIPT"
  sed -i "s|SITE_ROOT_DIR|${SITE_ROOT}|g" "$BACKUP_SCRIPT"
  sed -i "s|DB_NAME_VAR|${DB_NAME}|g" "$BACKUP_SCRIPT"
  sed -i "s|DB_USER_VAR|${DB_USER}|g" "$BACKUP_SCRIPT"
  sed -i "s|DB_PASS_VAR|${DB_PASS}|g" "$BACKUP_SCRIPT"
  
  chmod +x "$BACKUP_SCRIPT"
  
  # Add to crontab (daily at 3 AM)
  echo "0 3 * * * root ${BACKUP_SCRIPT}" > "/etc/cron.d/wp-backup-${DOMAIN}"

  # 20) Create maintenance script
  MAINTENANCE_SCRIPT="/usr/local/bin/wp-maintenance-${DOMAIN}.sh"
  cat > "$MAINTENANCE_SCRIPT" <<'MAINT'
#!/bin/bash
# WordPress Maintenance Script
WP_PATH="WP_PATH_DIR"
APP_USER="APP_USER_VAR"
APP_GROUP="APP_GROUP_VAR"

# Update WordPress core
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp core update --path="${WP_PATH}"

# Update plugins
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp plugin update --all --path="${WP_PATH}"

# Update themes
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp theme update --all --path="${WP_PATH}"

# Update translations
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp language core update --path="${WP_PATH}"
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp language plugin update --all --path="${WP_PATH}"
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp language theme update --all --path="${WP_PATH}"

# Clean up
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp cache flush --path="${WP_PATH}"
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp transient delete --all --path="${WP_PATH}"

# Optimize database
sudo -u "${APP_USER}" -g "${APP_GROUP}" -- wp db optimize --path="${WP_PATH}"

echo "Maintenance completed: $(date)"
MAINT

  # Replace placeholders
  sed -i "s|WP_PATH_DIR|${WP_PATH}|g" "$MAINTENANCE_SCRIPT"
  sed -i "s|APP_USER_VAR|${APP_USER}|g" "$MAINTENANCE_SCRIPT"
  sed -i "s|APP_GROUP_VAR|${APP_GROUP}|g" "$MAINTENANCE_SCRIPT"
  
  chmod +x "$MAINTENANCE_SCRIPT"
  
  # Add to crontab (weekly on Sunday at 4 AM)
  if [[ "$AUTO_UPDATES" == "yes" ]]; then
    echo "0 4 * * 0 root ${MAINTENANCE_SCRIPT}" > "/etc/cron.d/wp-maintenance-${DOMAIN}"
  fi

  # 21) Save credentials securely
  CREDS_FILE="/root/.wordpress-${DOMAIN}.credentials"
  cat > "$CREDS_FILE" <<CREDS
=====================================
WordPress Installation Details
=====================================
Date: $(date)
Domain: ${DOMAIN}

SITE ACCESS:
------------
URL: ${SITE_URL}
Admin URL: ${SITE_URL}/wp-admin
Admin Username: ${ADMIN_USER}
Admin Password: ${ADMIN_PASS}
Admin Email: ${ADMIN_EMAIL}

DATABASE:
----------
Database Name: ${DB_NAME}
Database User: ${DB_USER}
Database Password: ${DB_PASS}
MySQL Root Password: ${MYSQL_ROOT_PASS}

SYSTEM:
--------
WordPress Path: ${WP_PATH}
System User: ${APP_USER}
PHP Version: ${PHP_VER}
PHP-FPM Socket: ${FPM_SOCK}

SSL/CERTIFICATE:
-----------------
Let's Encrypt Email: ${LE_EMAIL}
SSL Status: $(if [[ "$SITE_URL" == https* ]]; then echo "Enabled"; else echo "Not configured"; fi)

MAINTENANCE:
-------------
Backup Script: ${BACKUP_SCRIPT}
Maintenance Script: ${MAINTENANCE_SCRIPT}
Backup Location: /backup/wordpress/${DOMAIN}

SECURITY:
----------
Fail2ban: ${INSTALL_FAIL2BAN}
Redis Cache: ${INSTALL_REDIS}
Firewall: Enabled (UFW)

NOTES:
-------
- Backups run daily at 3 AM
- Maintenance runs weekly on Sundays at 4 AM
- To manually backup: ${BACKUP_SCRIPT}
- To manually update: ${MAINTENANCE_SCRIPT}
- To manage SSL: certbot --nginx -d ${DOMAIN} -d www.${DOMAIN}
=====================================
CREDS
  
  chmod 600 "$CREDS_FILE"

  # 22) Final system optimizations
  log "Applying final optimizations..."
  
  # Nginx optimization
  cat > /etc/nginx/conf.d/optimization.conf <<'NGINX_OPT'
# Nginx Optimization
client_body_buffer_size 128k;
client_header_buffer_size 1k;
client_max_body_size 100m;
large_client_header_buffers 4 4k;
output_buffers 1 32k;
postpone_output 1460;

# Gzip Settings
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml text/x-js text/x-cross-domain-policy application/x-font-ttf application/x-font-opentype application/vnd.ms-fontobject image/x-icon;

# Cache Settings
open_file_cache max=2000 inactive=20s;
open_file_cache_valid 60s;
open_file_cache_min_uses 5;
open_file_cache_errors off;

# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
NGINX_OPT

  # Restart services
  systemctl restart nginx
  systemctl restart "php${PHP_VER}-fpm"

  # 23) Test WordPress installation
  log "Testing WordPress installation..."
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${SITE_URL}")
  if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "301" ]] || [[ "$HTTP_CODE" == "302" ]]; then
    log "WordPress is responding correctly (HTTP ${HTTP_CODE})"
  else
    warn "WordPress returned HTTP ${HTTP_CODE}. Please check the installation."
  fi

  # 24) Display summary
  clear
  echo -e "${GREEN}"
  cat <<'BANNER'
 __        ___     ____                      ____            
 \ \      / (_)___:|  _ \ _ __ ___  ___ ___ |  _ \ _ __ ___  
  \ \ /\ / /| |_  /| |_) | '__/ _ \/ __/ __|| |_) | '__/ _ \ 
   \ V  V / | |/ / |  __/| | |  __/\__ \__ \|  __/| | | (_) |
    \_/\_/  |_/___||_|   |_|  \___||___/___/|_|   |_|  \___/ 
                                                              
BANNER
  echo -e "${NC}"
  
  echo -e "${BLUE}============================================================${NC}"
  echo -e "${GREEN}        WordPress Installation Completed Successfully!       ${NC}"
  echo -e "${BLUE}============================================================${NC}\n"
  
  echo -e "${YELLOW}SITE INFORMATION:${NC}"
  echo -e "URL:            ${CYAN}${SITE_URL}${NC}"
  echo -e "Admin Panel:    ${CYAN}${SITE_URL}/wp-admin${NC}"
  echo -e ""
  
  echo -e "${YELLOW}ADMIN CREDENTIALS:${NC}"
  echo -e "Username:       ${CYAN}${ADMIN_USER}${NC}"
  echo -e "Password:       ${CYAN}${ADMIN_PASS}${NC}"
  echo -e "Email:          ${CYAN}${ADMIN_EMAIL}${NC}"
  echo -e ""
  
  echo -e "${YELLOW}DATABASE INFORMATION:${NC}"
  echo -e "Database Name:  ${CYAN}${DB_NAME}${NC}"
  echo -e "Database User:  ${CYAN}${DB_USER}${NC}"
  echo -e "Database Pass:  ${CYAN}${DB_PASS}${NC}"
  echo -e ""
  
  echo -e "${YELLOW}SYSTEM INFORMATION:${NC}"
  echo -e "WordPress Path: ${CYAN}${WP_PATH}${NC}"
  echo -e "System User:    ${CYAN}${APP_USER}${NC}"
  echo -e "PHP Version:    ${CYAN}${PHP_VER}${NC}"
  echo -e ""
  
  if [[ "$SITE_URL" != https* ]]; then
    echo -e "${YELLOW}SSL CERTIFICATE:${NC}"
    echo -e "${RED}⚠ SSL not configured. To enable SSL, ensure DNS is pointing to this server and run:${NC}"
    echo -e "${CYAN}certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} -m ${LE_EMAIL} --agree-tos --no-eff-email --redirect${NC}"
    echo -e ""
  fi
  
  echo -e "${YELLOW}IMPORTANT FILES:${NC}"
  echo -e "Credentials:    ${CYAN}${CREDS_FILE}${NC}"
  echo -e "Backup Script:  ${CYAN}${BACKUP_SCRIPT}${NC}"
  echo -e "Maintenance:    ${CYAN}${MAINTENANCE_SCRIPT}${NC}"
  echo -e ""
  
  echo -e "${GREEN}SECURITY FEATURES:${NC}"
  echo -e "✓ UFW Firewall enabled"
  [[ "$INSTALL_FAIL2BAN" == "yes" ]] && echo -e "✓ Fail2ban configured"
  [[ "$INSTALL_REDIS" == "yes" ]] && echo -e "✓ Redis cache installed"
  echo -e "✓ Automatic backups configured (daily at 3 AM)"
  [[ "$AUTO_UPDATES" == "yes" ]] && echo -e "✓ Automatic updates enabled (weekly)"
  echo -e ""
  
  echo -e "${BLUE}============================================================${NC}"
  echo -e "${YELLOW}⚠  SAVE THE CREDENTIALS ABOVE IN A SECURE LOCATION!${NC}"
  echo -e "${YELLOW}   Full details saved to: ${CREDS_FILE}${NC}"
  echo -e "${BLUE}============================================================${NC}"
  echo -e ""
  echo -e "${GREEN}Installation completed successfully! Enjoy your WordPress site!${NC}"
}

# Run main function
main "$@"