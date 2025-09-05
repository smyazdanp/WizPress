#!/bin/bash

# --- Functions ---

# Function to display messages
log_message() {
    echo "[INFO] $1"
}

# Function to display errors and exit
error_exit() {
    echo "[ERROR] $1"
    exit 1
}

# Function to prompt for user input with a default value
get_input_with_default() {
    local prompt_text="$1"
    local default_value="$2"
    local input_var_name="$3"
    read -p "$prompt_text (default: $default_value): " user_input
    if [ -z "$user_input" ]; then
        eval "$input_var_name=\'$default_value\'"
    else
        eval "$input_var_name=\'$user_input\'"
    fi
}

# Function to validate a port number
validate_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1024 )) || (( port > 65535 )); then
        error_exit "Invalid port number: $port. Port must be a number between 1024 and 65535."
    fi
}

# Function to validate domain name
validate_domain() {
    local domain=$1
    if [ -z "$domain" ]; then
        error_exit "Domain name cannot be empty."
    fi
    if ! [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        error_exit "Invalid domain name format: $domain."
    fi
}

# --- Main Script Start ---
log_message "Starting WordPress Auto-Installer for Ubuntu Server"

# --- User Input ---
log_message "Gathering configuration details..."

get_input_with_default "Enter your domain name (e.g., example.com)" "yourdomain.com" DOMAIN_NAME
validate_domain "$DOMAIN_NAME"

get_input_with_default "Enter SSH port" "2222" SSH_PORT
validate_port "$SSH_PORT"

get_input_with_default "Enter HTTP port" "8080" HTTP_PORT
validate_port "$HTTP_PORT"

get_input_with_default "Enter HTTPS port" "8443" HTTPS_PORT
validate_port "$HTTPS_PORT"

get_input_with_default "Enter MySQL port" "3307" MYSQL_PORT
validate_port "$MYSQL_PORT"

log_message "Ports configured: SSH=$SSH_PORT, HTTP=$HTTP_PORT, HTTPS=$HTTPS_PORT, MySQL=$MYSQL_PORT"

# 1. Server Preparation
log_message "Updating system packages..."
sudo apt update && sudo apt upgrade -y || error_exit "Failed to update system packages."

log_message "Installing essential packages (Nginx, PHP-FPM, MySQL/MariaDB, Certbot, WP-CLI)..."
sudo apt install -y nginx php-fpm php-mysql php-cli php-json php-common php-zip php-gd php-mbstring php-curl php-xml php-bcmath php-soap php-intl mariadb-server mariadb-client certbot python3-certbot-nginx wget unzip || error_exit "Failed to install essential packages."

log_message "Configuring UFW firewall..."
sudo ufw enable || error_exit "Failed to enable UFW."
sudo ufw allow $SSH_PORT/tcp comment 'Custom SSH Port' || error_exit "Failed to allow custom SSH port."
sudo ufw allow $HTTP_PORT/tcp comment 'Custom HTTP Port' || error_exit "Failed to allow custom HTTP port."
sudo ufw allow $HTTPS_PORT/tcp comment 'Custom HTTPS Port' || error_exit "Failed to allow custom HTTPS port."
sudo ufw allow $MYSQL_PORT/tcp comment 'Custom MySQL Port' || error_exit "Failed to allow custom MySQL port."
sudo ufw reload || error_exit "Failed to reload UFW rules."
log_message "UFW configured successfully."

# 2. Nginx and PHP-FPM Configuration
log_message "Configuring Nginx and PHP-FPM..."

sudo tee /etc/nginx/sites-available/wordpress <<EOF
server {
    listen $HTTP_PORT;
    listen $HTTPS_PORT ssl;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;

    root /var/www/html/wordpress;
    index index.php index.html index.htm;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php\$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/ || error_exit "Failed to create Nginx symlink."
sudo nginx -t && sudo systemctl restart nginx || error_exit "Failed to configure Nginx."
sudo systemctl restart php\$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;")-fpm || error_exit "Failed to restart PHP-FPM."

log_message "Nginx and PHP-FPM configured successfully."

# 3. WordPress Installation
log_message "Downloading and extracting WordPress..."

mkdir -p /var/www/html || error_exit "Failed to create /var/www/html directory."
cd /tmp || error_exit "Failed to change directory to /tmp."
wget -q https://wordpress.org/latest.tar.gz || error_exit "Failed to download WordPress."
tar -xzf latest.tar.gz || error_exit "Failed to extract WordPress."
sudo mv wordpress /var/www/html/wordpress || error_exit "Failed to move WordPress to /var/www/html."
sudo chown -R www-data:www-data /var/www/html/wordpress || error_exit "Failed to set ownership for WordPress directory."
sudo chmod -R 755 /var/www/html/wordpress || error_exit "Failed to set permissions for WordPress directory."
rm latest.tar.gz || error_exit "Failed to remove latest.tar.gz."

log_message "WordPress downloaded and extracted successfully."

# 4. Database Setup
log_message "Creating MySQL/MariaDB database and user..."

DB_NAME="wordpress_db"
DB_USER="wordpress_user"
DB_PASS="\$(openssl rand -base64 12)"

sudo mysql -e "CREATE DATABASE IF NOT EXISTS \${DB_NAME} DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;" || error_exit "Failed to create database."
sudo mysql -e "GRANT ALL ON \${DB_NAME}.* TO '\${DB_USER}'@'localhost' IDENTIFIED BY '\${DB_PASS}';" || error_exit "Failed to create database user."
sudo mysql -e "FLUSH PRIVILEGES;" || error_exit "Failed to flush privileges."

log_message "Database '\${DB_NAME}' and user '\${DB_USER}' created successfully."

# 5. WordPress Configuration
log_message "Configuring WordPress wp-config.php..."

sudo cp /var/www/html/wordpress/wp-config-sample.php /var/www/html/wordpress/wp-config.php || error_exit "Failed to copy wp-config-sample.php."
sudo sed -i "s/database_name_here/\${DB_NAME}/g" /var/www/html/wordpress/wp-config.php || error_exit "Failed to set DB_NAME in wp-config.php."
sudo sed -i "s/username_here/\${DB_USER}/g" /var/www/html/wordpress/wp-config.php || error_exit "Failed to set DB_USER in wp-config.php."
sudo sed -i "s/password_here/\${DB_PASS}/g" /var/www/html/wordpress/wp-config.php || error_exit "Failed to set DB_PASS in wp-config.php."

SALT_KEYS=\$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
sudo sed -i ":a;N;s/put your unique phrase here/\$SALT_KEYS/;ta" /var/www/html/wordpress/wp-config.php || error_exit "Failed to set SALT_KEYS in wp-config.php."

log_message "WordPress wp-config.php configured successfully."

# 6. SSL Certificate and Domain Configuration
log_message "Installing Certbot and obtaining SSL certificate..."

sudo certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME --non-interactive --agree-tos --email admin@$DOMAIN_NAME || error_exit "Failed to obtain SSL certificate with Certbot."

log_message "SSL certificate obtained and configured successfully."
log_message "Setting up automatic SSL renewal..."

(crontab -l 2>/dev/null; echo "0 0 * * * /usr/bin/certbot renew --quiet") | crontab -

log_message "Automatic SSL renewal configured."

# 7. Final WordPress Setup
log_message "Running WordPress CLI commands for initial setup..."

WP_ADMIN_USER="admin"
WP_ADMIN_PASS="\$(openssl rand -base64 12)"
WP_ADMIN_EMAIL="admin@$DOMAIN_NAME"

sudo -u www-data wp core install --path=/var/www/html/wordpress --url="https://$DOMAIN_NAME:$HTTPS_PORT" --title="My WordPress Site" --admin_user="\$WP_ADMIN_USER" --admin_password="\$WP_ADMIN_PASS" --admin_email="\$WP_ADMIN_EMAIL" --allow-root || error_exit "Failed to install WordPress via WP-CLI."

log_message "WordPress initial setup complete."
log_message "Installation complete!"
log_message "You can access your WordPress dashboard at: https://$DOMAIN_NAME:$HTTPS_PORT/wp-admin"
log_message "Your WordPress Admin Username: \$WP_ADMIN_USER"
log_message "Your WordPress Admin Password: \$WP_ADMIN_PASS"
log_message "Please save these credentials securely."

# --- End of Script ---


