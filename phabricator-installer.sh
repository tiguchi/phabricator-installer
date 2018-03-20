#!/usr/bin/env bash

#
# Phabricator Installer Script for Debian
#
# Version:	1.0.1
# Author:	Thomas Iguchi
# Web:		https://github.com/tiguchi/phabricator-installer
#

# Detect OS and version
# Following if-else block from https://unix.stackexchange.com/a/6348
if [ -f /etc/os-release ]; then
	. /etc/os-release
	OS="$NAME"
	VER="$VERSION_ID"
elif type lsb_release >/dev/null 2>&1; then
	OS=$(lsb_release -si)
	VER=$(lsb_release -sr)
elif [ -f /etc/lsb-release ]; then
	. /etc/lsb-release
	OS="$DISTRIB_ID"
	VER="$DISTRIB_RELEASE"
elif [ -f /etc/debian_version ]; then
	OS=Debian
	VER=$(cat /etc/debian_version)
else
	OS=$(uname -s)
	VER=$(uname -r)
fi

# TODO This script probably needs just minor adjustments for Ubuntu
# for now we support just Debian (tested on Stretch)
if [[ ! "$OS" =~ Debian ]]; then
	echo "Cannot install Phabricator: unsupported OS"
	exit 1;
fi

# Desired PHP version
PHP_VERSION="php5"

# Determine PHP version for OS

if [[ "$OS" =~ Debian && "$VER" =~ 9\.? ]]; then
	# Phabricator is incompatible with php7.0 and Debian 9 dropped support for PHP 5.x
	PHP_VERSION="php7.1"
fi

MYSQL_PACKAGE="mysql-server"
UFW_PACKAGE="ufw"
CERTBOT_PACKAGE="certbot"

# Programs
GIT="git"

DNS_SERVER="resolver1.opendns.com"

LIBPHUTIL_REPO_URL="https://github.com/phacility/libphutil.git"
ARCANIST_REPO_URL="https://github.com/phacility/arcanist.git"
PHABRICATOR_REPO_URL="https://github.com/phacility/phabricator.git"

REPO_SSHD_CONFIG="/etc/ssh/sshd_config.phabricator"
REPO_SSHD_SERVICE="ssh-phabricator.service"
SSHD_CONF_FILE="/etc/ssh/sshd_config"
APHLICT_SERVICE="aphlict.service"

SELF_SIGNED_CERTS_DIR="/etc/ssl/localcerts"

ME=`whoami`

shopt -s nocasematch

function update_base_packages() {
	# Basic packages (min requirement)
	PACKAGES="git pwgen logrotate dnsutils sendmail nginx mysql-client python-pygments $PHP_VERSION $PHP_VERSION-fpm $PHP_VERSION-mysql $PHP_VERSION-gd $PHP_VERSION-curl $PHP_VERSION-apcu $PHP_VERSION-cli $PHP_VERSION-json $PHP_VERSION-dev $PHP_VERSION-mbstring"
}

# Run something as the specified user
function as_user() {
        if [ "$ME" == "$1" ]; then
                bash -c "$2"
        else
                sudo -u "$1" -s /bin/sh -c "$2"
        fi

	if ! [ "$?" -eq 0 ]; then
		error "Error while running the following command as user '$1': $2"
		exit 1
	fi
}

function pushd () {
    command pushd "$@" > /dev/null
}

function popd () {
    command popd "$@" > /dev/null
}

function check_is_installed() {
	result=$(apt-cache policy "$1" | grep "Installed: (none)")

	if [[ -z "$result" ]]; then
		return 0
	else
		return 1
	fi
}

function hr() {
	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' =
}

function header() {
	echo
	hr
	echo -e " \e[92m\e[1m$1\e[0m"
	hr
	echo
}

function ok() {
	echo -e "[  \e[1m\e[92mOK\e[0m  ] $1"
}

function info() {
	echo -e "[ \e[1m\e[96mINFO\e[0m ] $1"
}

function warn() {
        echo -e "[ \e[1m\e[93mWARN\e[0m ] $1"
}

function error() {
        echo -e "[ \e[1m\e[91mFAIL\e[0m ] $1"
}

function prepare_repositories {
	header "Checking repositories for $PHP_VERSION packages"

	FOUND=`sudo apt-cache search "$PHP_VERSION"`

	if [[ -z "$FOUND" ]]; then
		info "Installing repository that provides $PHP_VERSION packages..."

		sudo apt-get install -y apt-transport-https lsb-release ca-certificates wget
		sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
		echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee --append "/etc/apt/sources.list.d/$PHP_VERSION.list" > /dev/null
		sudo apt-get update
		return $?
	fi
}

function update_package_cache {
	header "Updating package cache"

	if ! sudo apt-get update; then
		error "Error while trying to update package cache"
		exit 1
	fi
}

function install_requirements {
	header "Installing dependency packages"
	update_base_packages

	if ! sudo apt-get -y install $PACKAGES; then
		error "Error while trying to install base requirement packages."
		exit 1
	fi
}

function confirm() {
	if [[ "$2" =~ ^[yY]$ ]]; then
		default=0
		options="[Y/n]"
	else
		default=1
		options="[y/N]"
	fi

	label=$'\e[1m\e[92m'"$1 $options:"$' \e[0m'
	read -n1 -r -p "$label" response
	echo

	if [[ "$response" =~ ^[yY]$ ]]; then
		return 0
	else
		if [[ -z "$response" ]]; then
			return $default
		else
			return 1
		fi
	fi
}

function prompt() {
	var=""
	label=$'\e[1m\e[92m'$1$': \e[0m'

	while [ -z "$var" ]; do
		read -e -p "$label" -i "$2" var
	done

	eval "$3=\$var"
}

function prompts() {
	var=""
	label=$'\e[1m\e[92m'$1$': \e[0m'

	while [ -z "$var" ]; do
		read -s -e -p "$label" var
	done
	echo
	eval "$2=\$var"
}

function create_user() {
	exists=$(id -u $1 > /dev/null 2>&1; echo $?)

	if [ "$exists" -eq 0 ]; then
		info "System user '$1' already exists"
	else
		ok "Creating system user '$1'"
		sudo useradd -r "$1"
	fi
}

function add_user_to_group() {
	USER="$1"
	GROUP="$2"
	sudo usermod -a -G "$GROUP" "$USER"
	ok "User $USER added to group $GROUP"
}

function create_directory() {
	if [ -d "$1" ]; then
		warn "$1 already exists"
	else
		ok "Creating directory $1"
		sudo mkdir -p "$1"
	fi

	sudo chown $2:$2 -R "$1"
}

function install_repository() {
	if [ -d "$2" ]; then
		info "$2 already exists. Pulling latest changes if available..."
		pushd "$2"
		# Maintain shallow clone as follows
		as_user "$NGINX_USER" "git fetch --depth 1"
		as_user "$NGINX_USER" "git reset --hard origin/stable"
		popd
	else
		# Check out as shallow clone of origin/stable branch... much faster than full repo clone
		as_user "$NGINX_USER" "git clone --depth 1 --branch stable \"$1\" \"$2\""
		ok "$2 installed"
	fi
}

function create_backup() {
	FILE="$1"
	DIR="$(dirname "$FILE")"
	BASENAME="$(basename "$FILE")"
	EXT="${BASENAME##*.}"

	if [[ ! -z "$EXT" ]]; then
		EXT=".$EXT"
	fi

	EXT="$EXT.bak"
	BASENAME="${BASENAME%.*}"
	TODAY=`date +%Y%m%d`
	SEQ=0
	SUFFIX="-$TODAY"
	TRG="$DIR/$BASENAME$SUFFIX$EXT"

	while [ -e "$TRG" ]; do
		SEQ=$(( $SEQ + 1 ))
    		SUFFIX="-$TODAY-$SEQ"
		TRG="$DIR/$BASENAME$SUFFIX$EXT"
	done

	sudo touch "$TRG"
	sudo cp "$FILE" "$TRG"
	sudo chmod 600 "$TRG"
	ok "Backup created - $FILE => $TRG"
}

function write_config() {
	FILE="$1"
	OWNER="$2"
	BODY=`cat`

	if [ -f "$FILE" ]; then
                warn "Configuration file $FILE already exists."
		create_backup "$FILE"
	fi

        ok "Writing configuration file $FILE..."
	# Create directory structure in case it doesn't exist yet
	sudo install -D /dev/null "$FILE"
        echo "$BODY" | sudo tee "$FILE" > /dev/null
        sudo chown "$OWNER" "$FILE"
}

function get_wan_inet_address() {
	dig +short myip.opendns.com "@$DNS_SERVER"
}

function get_domain_ip() {
	dig +short "$1" "@$DNS_SERVER"
}

MY_CLIENT_CNF_FILE=`pwd`'/my_tmp.cnf'

# Store credentials in a file instead of passing in as program arguments
# so password cannot be potentially seen in ps output
function create_mysql_connection_config() {
	USER="$1"
	PW="${2@Q}"
	HOST="$3"
	PORT="$4"

	touch $MY_CLIENT_CNF_FILE
	chmod 600 $MY_CLIENT_CNF_FILE
	cat <<EOF > $MY_CLIENT_CNF_FILE
[client]
user=$USER
password=$PW
port=$PORT
host=$HOST
EOF
}

function remove_mysql_connection_config() {
	if [[ -f "$MY_CLIENT_CNF_FILE" ]]; then
		rm "$MY_CLIENT_CNF_FILE"
	fi
}

function run_sql() {
	USER="$2"
	SQL=$(cat /dev/stdin)

	if [[ -z "$USER" ]]; then
		# Localhost
		COMMAND="sudo mysql"
	else
		# Remote server
		create_mysql_connection_config "$2" "$3" "$4" "$5"
		COMMAND="mysql --defaults-extra-file=$MY_CLIENT_CNF_FILE"
	fi

	# Skip the first line which is just column names
	RESULT=$($COMMAND <<<"$SQL" | tail -n +2)
	MY_RESULT=$?

	# In case it's remote server (see above)
	remove_mysql_connection_config

	if ! [ $MY_RESULT -eq 0 ]; then
		error "Error while running the following SQL query: $SQL"
		exit 1
	fi

	eval "$1=\$RESULT"
}

function test_mysql_server() {
	create_mysql_connection_config "$@"
	RESULT=$(mysql --defaults-extra-file="$MY_CLIENT_CNF_FILE" -e "SELECT 1 AS SUCCESS" 2>&1)
	remove_mysql_connection_config

	if [[ "$RESULT" == *"Access denied"* ]]; then
		return 1
	else
		if [[ "$RESULT" == *"SUCCESS"* ]]; then
			return 0;
		else
			error "$RESULT"
			exit 1;
		fi
	fi
}

function ph_config() {
	pushd "$PHABRICATOR_INSTALL_DIR/phabricator/bin"
	sudo ./config set "$1" "$2"
	popd
}

function ssh_config() {
	PROP="$1"
	VALUE="$2"
	RX="^#* *$PROP "

	if grep -q "$RX" "$SSHD_CONF_FILE"; then
		RX="s/^(#?$PROP)([[:space:]]+)(.*)/$PROP\2$VALUE/"
		sudo sed -re "$RX" -i.`date -I` "$SSHD_CONF_FILE"
	else
		echo "$PROP $VALUE" | sudo tee -a "$SSHD_CONF_FILE" > /dev/null
	fi
}

function ph_storage() {
	pushd "$PHABRICATOR_INSTALL_DIR/phabricator/bin"
	RESULT=$(sudo ./storage "$@" | tee /dev/tty)
	popd

	# It looks like the storage script also returns 0 in case of errors
	# therefore we need to search the output for "error"
	if [[ $RESULT =~ error ]]; then
		return 1
	else
		return 0
	fi
}

# --------------------------------------------------------------------------------------------
header "Phabricator Installation"

echo "The installation requires sudo rights and will prompt you for your password."
echo "You can interrupt the process anytime by pressing <Ctrl> + <C>"
echo

if ! confirm "Do you want to proceed?" "Y"; then
	info "OK, abort"
	exit 1
fi

update_package_cache
prepare_repositories
install_requirements

# --------------------------------------------------------------------------------------------
header "Configuration Options"

echo "Keep hitting <Enter> if you are uncertain or want to keep the default option if available"
echo

prompt "Under which domain should Phabricator be hosted? (e.g. phabricator.mydomain.com)" "" DOMAIN_NAME

DOMAIN_INET_ADDR=$(get_domain_ip "$DOMAIN_NAME")
WAN_INET_ADDR=$(get_wan_inet_address)

if [[ "$DOMAIN_INET_ADDR" != "$WAN_INET_ADDR" ]]; then
	if [[ "$DOMAIN_INET_ADDR" ]]; then
		warn "$DOMAIN_NAME is currently assigned to a different IP address ($DOMAIN_INET_ADDR). It should point to this server's IP address $WAN_INET_ADDR"
	else
		warn "$DOMAIN_NAME does not seem to exist or does not have a properly configured A record that resolves to an IP address"
	fi

	echo
	echo "You should fix this by editing your domain's DNS records before you proceed."
	echo "The optional installation of a Let's Encrypt SSL certificate later on will require that $DOMAIN_NAME resolves to this server!"
	echo

	if ! confirm "Do you want to continue anyway?" "N"; then
		info "OK, see you in a bit"
		exit 1
	fi
fi

prompt "Phabricator installation directory" "/srv/www/$DOMAIN_NAME" PHABRICATOR_INSTALL_DIR
prompt "Phabricator daemon user" "phabricator" PHABRICATOR_DAEMON_USER
prompt "Phabricator database user name" "phabricator" DB_USER
prompt "Phabricator database namespace (default = phabricator)" "phabricator" DB_NAMESPACE
#prompt "Nginx web user" "www-data" NGINX_USER
# This script does not change the default web server user
NGINX_USER="www-data"

# --------------------------------------------------------------------------------------------
header "SSL Configuration"

if confirm "Would you like to use Let's Encrypt for securing Phabricator with a free SSL certificate (recommended)?" "Y"; then
	SSL_CERTIFICATE="/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
	SSL_CERTIFICATE_KEY="/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"

	if ! check_is_installed certbot; then
		sudo apt-get -y install certbot
		ok "certbot installed"
	fi

	info "Running certbot for creating a certificate for $DOMAIN_NAME"
	sudo certbot certonly --rsa-key-size 4096 --authenticator standalone -d "$DOMAIN_NAME" --pre-hook "nginx -s stop" --post-hook "nginx"
else
	if confirm "Would you like to use your own SSL certificate? (y = provide file paths, n = auto-generate self-signed cert)" "N"; then
		echo
		echo "We need to secure your Phabricator web server using SSL. If you are uncertain about the following two configuration steps"
		echo "then just hit enter and edit the Nginx configuration file generated by the installer after the installation has been completed."
		echo
		prompt "SSL certificate location" "$SELF_SIGNED_CERTS_DIR/please-edit-this-path-cert.pem" SSL_CERTIFICATE
		prompt "SSL certificate key location" "$SELF_SIGNED_CERTS_DIR/please-edit-this-path-privkey.pem" SSL_CERTIFICATE_KEY
	else
		info "Generating self-signed SSL certificate"

		if ! check_is_installed openssl; then
			sudo apt-get -y install openssl
			ok "OpenSSL installed"
		fi

		create_directory "$SELF_SIGNED_CERTS_DIR" "root"
		SSL_CERTIFICATE="$SELF_SIGNED_CERTS_DIR/$DOMAIN_NAME.pem"
		SSL_CERTIFICATE_KEY="$SELF_SIGNED_CERTS_DIR/$DOMAIN_NAME.key"

		if [ -e "$SSL_CERTIFICATE_KEY" ]; then
			warn "Self-signed certificate $SSL_CERTIFICATE already exists"
		else
			info "Generating self-signed certificated"
			sudo openssl req -new -x509 -days 365 -nodes -out "$SSL_CERTIFICATE" -keyout "$SSL_CERTIFICATE_KEY"
			info "$SSL_CERTIFICATE and $SSL_CERTIFICATE_KEY created"
		fi
	fi
fi

# --------------------------------------------------------------------------------------------
header "SSH Configuration"

echo "We're about to set up an additional locked down SSH daemon that will be used for processing secure repository access"
echo "and we need to assign it a port number. In order to prevent ugly looking repository checkout or clone URLs such as:"
echo
echo "git clone ssh://git@$DOMAIN_NAME:2222/my-repo.git"
echo
echo "we recommend to assign the default SSH port number 22 to the repository access SSH daemon and re-assign a"
echo "different SSH port number to the regular maintenance SSH daemon that allows you to remotely log into this server."
echo
echo "The installer will pre-select the \"pretty URL\" configuration for you with the default port being"
echo "assigned to the repository SSH daemon."
echo
prompt "Repository SSH user (SSH user for committing to repositories)" "git" VCS_USER
prompt "Repository SSH port (recommended = 22)" "22" REPO_SSH_PORT
prompt "Maintenance SSH port (default = 22)" "2222" MAINTENANCE_SSH_PORT

if [[ "$MAINTENANCE_SSH_PORT" != "22" ]]; then
	warn "Make sure to write down and remember the non-standard maintenance SSH port number: $MAINTENANCE_SSH_PORT"
	echo
	echo "You may want to update your local ~/.ssh/config script with the following lines:"
	echo
	echo "Host $DOMAIN_NAME"
    	echo "    HostName $WAN_INET_ADDR"
	echo "    User $ME"
	echo "    Port $MAINTENANCE_SSH_PORT"
	echo
fi

prompt "Repository storage location" "/srv/phabricator/repos" REPO_PATH
prompt "File upload storage location" "/srv/phabricator/files" FILE_STORAGE_PATH

# --------------------------------------------------------------------------------------------
header "Creating Users and Directories"

create_user "$PHABRICATOR_DAEMON_USER"
create_user "$NGINX_USER"
create_user "$VCS_USER"

# Add users to phabricator group for file storage read / write access
add_user_to_group "$NGINX_USER" "$PHABRICATOR_DAEMON_USER"
add_user_to_group "$VCS_USER" "$PHABRICATOR_DAEMON_USER"

# Workaround for a problem where SSHD refuses auth for VCS user
sudo passwd -d "$VCS_USER"
sudo usermod --shell /bin/sh "$VCS_USER"
# Also needs a home directory to prevent warning messages from shell
create_directory "/home/$VCS_USER" "$VCS_USER"
sudo usermod -d "/home/$VCS_USER" "$VCS_USER"

create_directory "$PHABRICATOR_INSTALL_DIR" 	"$NGINX_USER"
create_directory "$REPO_PATH" 			"$PHABRICATOR_DAEMON_USER"
create_directory "$FILE_STORAGE_PATH" 		"$PHABRICATOR_DAEMON_USER"

# Give also phabricator group full access
sudo chmod 770 "$REPO_PATH"
sudo chmod 770 "$FILE_STORAGE_PATH"

# --------------------------------------------------------------------------------------------
header "Downloading Phabricator from GitHub"

install_repository "$LIBPHUTIL_REPO_URL" "$PHABRICATOR_INSTALL_DIR/libphutil"
install_repository "$ARCANIST_REPO_URL" "$PHABRICATOR_INSTALL_DIR/arcanist"
install_repository "$PHABRICATOR_REPO_URL" "$PHABRICATOR_INSTALL_DIR/phabricator"

# --------------------------------------------------------------------------------------------
header "Setting up MySQL Database for use with Phabricator"

MYSQL_HOST="localhost"
MYSQL_PORT="3306"
MYSQL_USER_HOST="localhost"
MYSQL_ROOT_USER=""

if confirm "Do you want to use an external MySQL server on a different host?" "N"; then
	prompt "MySQL server IP address or host name" "" MYSQL_HOST
	prompt "MySQL server port (default = $MYSQL_PORT)" $MYSQL_PORT MYSQL_PORT
	MYSQL_USER_HOST="$WAN_INET_ADDR"

	echo
	echo "You need to have privileged remote access to the MySQL server \`$MYSQL_HOST\` so the installer can create"
	echo "a dedicated MySQL user for your Phabricator instance. Please provide your MySQL user credentials now:"
	echo

	while [[ -z "$MYSQL_ROOT_PASSWORD" ]]; do
		prompt "Privileged MySQL user" "$MYSQL_ROOT_USER" MYSQL_ROOT_USER
		prompts "Password" MYSQL_ROOT_PASSWORD

		if ! test_mysql_server "$MYSQL_ROOT_USER" "$MYSQL_ROOT_PASSWORD" "$MYSQL_HOST" "$MYSQL_PORT"; then
			error "Incorrect credentials, please try again"
			MYSQL_ROOT_PASSWORD=""
		fi
	done
else
	info "Using local MySQL database server for Phabricator"

	if ! check_is_installed $MYSQL_PACKAGE; then
		sudo apt-get install -y $MYSQL_PACKAGE
		ok "MySQL server installed"
	fi

	if confirm "It is highly recommended that you 'harden' (enhance security of) your MySQL database installation. Would like to do that now?" "Y"; then
		sudo mysql_secure_installation
		ok "MySQL server is hardened now"
	else
		warn "If you change your mind you can run the hardening script yourself later via 'sudo mysql_secure_installation'"
	fi
fi

info "Creating MySQL user \`$DB_USER\`"

# Set up db user for Phabricator

# End user doesn't need to know the password
DB_PASSWORD=$(pwgen 32 1)

run_sql DB_USER_EXISTS "$MYSQL_ROOT_USER" "$MYSQL_ROOT_PASSWORD" "$MYSQL_HOST" "$MYSQL_PORT" <<EOF
	SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = '$DB_USER')
EOF

if [[ "$DB_USER_EXISTS" == "1" ]]; then
	warn "Database user '$DB_USER' already exists."

	if confirm "Should a random database password be re-assigned to the existing '$DB_USER' user?" "N"; then
		run_sql RESULT <<EOF
			SET PASSWORD FOR '$DB_USER'@'localhost' = PASSWORD('$DB_PASSWORD');
EOF
	else
		while [[ "$DB_PASSWORD" != "$DB_PASSWORD_2"  ]]; do
			prompts "Please enter the password for '$DB_USER'" DB_PASSWORD
			prompts "Please re-enter the password" DB_PASSWORD_2

			if [[ "$DB_PASSWORD" != "$DB_PASSWORD_2" ]]; then
				error "Passwords don't match."
			fi
		done
	fi
else
	run_sql VOID <<EOF
		CREATE USER \`$DB_USER\`@\`localhost\` IDENTIFIED BY '$DB_PASSWORD';
EOF
	ok "Database user '$DB_USER' created"
fi

# Following part is important - the Phabricator DB user needs to be able to create new
# schemas under the specified namespace. Each Phabricator module will have its own schema
# for data storage, that's why we grant wildcard access to all schemas that are prefixed
# with the namespace
run_sql VOID <<EOF
	GRANT ALL privileges ON \`$DB_NAMESPACE\_%\`.* TO \`$DB_USER\`@\`$MYSQL_USER_HOST\`;
EOF

ph_config "mysql.user" "$DB_USER"
ph_config "mysql.pass" "$DB_PASSWORD"
ph_config "mysql.host" "$MYSQL_HOST"
ph_config "mysql.port" "$MYSQL_PORT"
ph_config "storage.default-namespace" "$DB_NAMESPACE"

ok "Updated Phabricator database configuration"

info "Running Phabricator's database installation script..."

if ! ph_storage --force upgrade; then
	error "There was a problem with installing Phabricator's databases. See above for more details"
	exit 1
fi

ok "Phabricator database schemas are installed"

# --------------------------------------------------------------------------------------------
header "Writing Configuration Files"

write_config "/etc/sudoers.d/phabricator" "root" <<EOF
$VCS_USER ALL=($PHABRICATOR_DAEMON_USER) SETENV: NOPASSWD: /usr/bin/git, /usr/bin/git-upload-pack, /usr/bin/git-receive-pack
$NGINX_USER ALL=($PHABRICATOR_DAEMON_USER) SETENV: NOPASSWD: /usr/bin/git, /usr/bin/git-http-backend

EOF

# Nginx configuration file for Phabricator web server
NGINX_CONFIGURATION="/etc/nginx/sites-available/$DOMAIN_NAME.conf"

write_config "$NGINX_CONFIGURATION" "root" <<EOF
#
# Phabricator Web Server configuration for domain $DOMAIN_NAME
#
# Automatically generated by phabricator-installer.sh
#

# Aphlict configuration
map \$http_upgrade \$connection_upgrade {
	default upgrade;
	'' close;
}

upstream websocket_pool {
	ip_hash;
	server 127.0.0.1:22280;
}

upstream php_fpm_socket {
    server unix:/run/php/$PHP_VERSION-fpm.sock;
}

# Permanent redirect from HTTP to HTTPS
server {
	listen 80;
	server_name $DOMAIN_NAME;
	return 301 https://\$host\$request_uri;
}

# Main web server configuration for Phabricator
server {
	listen 443 ssl;
	listen [::]:443 ssl;

	server_name $DOMAIN_NAME;
	root        $PHABRICATOR_INSTALL_DIR/phabricator/webroot;

	ssl_certificate $SSL_CERTIFICATE;
	ssl_certificate_key $SSL_CERTIFICATE_KEY;

	location / {
		index index.php;
		rewrite ^/(.*)\$ /index.php?__path__=/\$1 last;
	}

	location /index.php {
		fastcgi_pass   php_fpm_socket;
		fastcgi_index  index.php;

		# Required if PHP was built with --enable-force-cgi-redirect
		fastcgi_param  REDIRECT_STATUS    200;

		# Variables to make the \$_SERVER populate in PHP
		fastcgi_param  HTTPS 		  'on';
		fastcgi_param  SCRIPT_FILENAME    \$document_root\$fastcgi_script_name;
		fastcgi_param  QUERY_STRING       \$query_string;
		fastcgi_param  REQUEST_METHOD     \$request_method;
		fastcgi_param  CONTENT_TYPE       \$content_type;
		fastcgi_param  CONTENT_LENGTH     \$content_length;

		fastcgi_param  SCRIPT_NAME        \$fastcgi_script_name;

		fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
		fastcgi_param  SERVER_SOFTWARE    nginx/\$nginx_version;

		fastcgi_param  REMOTE_ADDR        \$remote_addr;
	}

	# Aphlict - notification server
	location = /ws/ {
		proxy_pass http://websocket_pool;
		proxy_http_version 1.1;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_read_timeout 999999999;
	}
}
EOF

info "Enabling Nginx configuration $NGINX_CONFIGURATION"
sudo ln -s "$NGINX_CONFIGURATION" "/etc/nginx/sites-enabled/$(basename "$NGINX_CONFIGURATION")"

SSH_HOOK_PROGRAM="/usr/libexec/phabricator-ssh-hook.sh"

write_config "$SSH_HOOK_PROGRAM" "root" <<EOF
#!/bin/sh

VCSUSER="$VCS_USER"
ROOT="$PHABRICATOR_INSTALL_DIR/phabricator"

if [ "\$1" != "\$VCSUSER" ];
then
  exit 1
fi

exec "\$ROOT/bin/ssh-auth" \$@
EOF

sudo chmod 755 "$SSH_HOOK_PROGRAM"

write_config "$REPO_SSHD_CONFIG" "root" <<EOF
AuthorizedKeysCommand $SSH_HOOK_PROGRAM
AuthorizedKeysCommandUser root
AllowUsers $VCS_USER
Port $REPO_SSH_PORT
Protocol 2
PermitRootLogin no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
PrintLastLog no
PasswordAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile none

PidFile /var/run/sshd-phabricator.pid
EOF

# --------------------------------------------------------------------------------------------
header "Configuring Phabricator"

ph_config "phabricator.base-uri" "https://$DOMAIN_NAME/"
ph_config "storage.local-disk.path" "$FILE_STORAGE_PATH"
ph_config "repository.default-local-path" "$REPO_PATH"
ph_config "diffusion.ssh-user" "$VCS_USER"

# --------------------------------------------------------------------------------------------
header "Installing new Services"

echo "We're about to install Phabricator services using systemd configuration files"
echo
info "Installing repository access SSH service"

write_config "/etc/systemd/system/$REPO_SSHD_SERVICE" "root" <<EOF
[Unit]
Description=Phabricator repository access SSH service
After=network.target auditd.service sshd.service
Before=phabricator.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh.phabricator
ExecStart=/usr/sbin/sshd -D -f "$REPO_SSHD_CONFIG" \$SSHD_OPTS
ExecReload=/usr/sbin/sshd -t -f "$REPO_SSHD_CONFIG"
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify

[Install]
WantedBy=multi-user.target
Alias=$REPO_SSHD_SERVICE
EOF

ok "Repository access SSH service installed"

if ! check_is_installed "nodejs"; then
	if ! check_is_installed "curl"; then
		sudo apt-get install -y curl
		ok "curl installed"
	fi

	info "Installing NodeJS"
	curl -sL https://deb.nodesource.com/setup_9.x | sudo -E bash -
	sudo apt-get install -y nodejs
	ok "NodeJS installed"
fi

info "Setting up Aphlict notification server"

# Install ws npm package
pushd "$PHABRICATOR_INSTALL_DIR/phabricator/support/aphlict/server"
sudo npm install ws
popd
ok "ws package installed with npm"

write_config "/etc/systemd/system/$APHLICT_SERVICE" "root" <<EOF
[Unit]
Description=Phabricator notification server
After=syslog.target network.target mysql.service nginx.service phabricator.service

[Service]
Type=forking
User=$PHABRICATOR_DAEMON_USER
Group=$PHABRICATOR_DAEMON_USER
ExecStart=$PHABRICATOR_INSTALL_DIR/phabricator/bin/aphlict start
ExecStop=$PHABRICATOR_INSTALL_DIR/phabricator/bin/aphlict stop

[Install]
WantedBy=multi-user.target
EOF

ok "Aphlict notification server installed"

# ..............................................................................................

info "Installing Phabricator service"

ph_config "phd.user" "$PHABRICATOR_DAEMON_USER"

write_config "/etc/systemd/system/phabricator.service" "root" <<EOF
[Unit]
Description=Phabricator Daemon
After=syslog.target network.target mysql.service
Before=nginx.service

[Service]
User=$PHABRICATOR_DAEMON_USER
Group=$PHABRICATOR_DAEMON_USER
Type=forking
ExecStart=$PHABRICATOR_INSTALL_DIR/phabricator/bin/phd start
ExecStop=$PHABRICATOR_INSTALL_DIR/phabricator/bin/phd stop

[Install]
WantedBy=multi-user.target
EOF

ok "Phabricator service installed and running"

# --------------------------------------------------------------------------------------------
header "Setting up maintenance scripts"

# Create upgrade script
write_config "$PHABRICATOR_INSTALL_DIR/upgrade.sh" "root" <<EOF
#!/bin/bash

ROOT="$PHABRICATOR_INSTALL_DIR"
NGINX_AVAILABLE="/etc/nginx/sites-available/$DOMAIN_NAME.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN_NAME.conf"
NGINX_USER="$NGINX_USER"
ME=\`whoami\`

pushd () {
    command pushd "\$@" > /dev/null
}

popd () {
    command popd "\$@" > /dev/null
}

function ok() {
	echo -e "[  \e[1m\e[92mOK\e[0m  ] \$1"
}

function info() {
	echo -e "[ \e[1m\e[96mINFO\e[0m ] \$1"
}

function warn() {
        echo -e "[ \e[1m\e[93mWARN\e[0m ] \$1"
}

function error() {
        echo -e "[ \e[1m\e[91mFAIL\e[0m ] \$1"
}

function as_user() {
        if [ \$ME = "\$1" ]; then
                bash -c "\$2"
        else
                sudo -u "\$1" -s /bin/sh -c "\$2"
        fi

	if ! [ \$? -eq 0 ]; then
		echo "Error while running the following command as user '\$1': \$2"
		exit 1
	fi
}

function update_repo() {
	pushd "\$1"
	# Maintain shallow clone as follows
	as_user "\$NGINX_USER" "git fetch --depth 1"
	as_user "\$NGINX_USER" "git reset --hard origin/stable"
	popd
}

if [[ -f "\$NGINX_ENABLED" ]]; then
	info "Disabling Phabricator website..."
	sudo rm "\$NGINX_ENABLED"
	sudo service nginx reload
	ok "Phabricator website disabled"
fi

info "Stopping repository SSH daemon..."
sudo service ssh-phabricator stop
ok "Repository SSH daemon stopped"
info "Stopping Aphlict notification server..."
sudo service aphlict stop
ok "Aphlict stopped"
info "Stopping Phabricator Daemon (this may take a while)..."
sudo service phabricator stop

if systemctl is-active --quiet service; then
	error "The Phabricator daemon could not be successfully stopped"
	return 1
fi

ok "PHD stopped"

info "Updating Phabricator from GitHub..."
update_repo "\$ROOT/libphutil"
update_repo "\$ROOT/arcanist"
update_repo "\$ROOT/phabricator"
ok "Phabricator updated"

info "Upgrading MySQL database storage..."
sudo "\$ROOT/phabricator/bin/storage" --force upgrade
ok "Storage upgraded"

info "Starting Phabricator Daemon..."
sudo service phabricator start
ok "PHD started"
info "Starting Aphlict notification server..."
sudo service aphlict start
ok "Aphlict started"
info "Starting repository SSH daemon..."
sudo service ssh-phabricator start
ok "Repository SSH daemon started"
info "Reloading PHP FPM for flushing OPCache..."
sudo service $PHP_VERSION-fpm reload
ok "PHP FPM reloaded"
info "Re-enabling Phabricator website..."
sudo ln -s "\$NGINX_AVAILABLE" "\$NGINX_ENABLED"
sudo service nginx reload
ok "Phabricator website re-enabled"
EOF

# --------------------------------------------------------------------------------------------
header "Securing your Server"

# Firewall configuration needs to be done last

CONFIGURE_FIREWALL=1

if check_is_installed ufw; then
	confirm "Do you want to let the installer set up firewall rules via UFW?" "Y"
	CONFIGURE_FIREWALL=$?
else
	if confirm "Do you also want to install UFW to let the installer set up firewall rules?" "Y"; then
		sudo apt-get -y install ufw
		CONFIGURE_FIREWALL=0
	fi
fi

if [ "$CONFIGURE_FIREWALL" -eq 0 ]; then
	echo
	warn "This script will set up firewall rules for you now. Depending on your chosen SSH port configuration this may"
	warn "disconnect you from the current remote shell session. This will be the case if you chose to change the SSHD"
	warn "port configuration to something completely different from your current SSHD port configuration (default = 22)."
	warn "If you want you can also install the rules by hand after installation has finished."
	echo

	if confirm "Are you ready to proceed and set up the firewall configuration now?" "Y"; then
		sudo ufw default deny incoming
		sudo ufw default allow outgoing
		sudo ufw allow http
		sudo ufw allow https
		sudo ufw allow $MAINTENANCE_SSH_PORT
		sudo ufw allow $REPO_SSH_PORT
		sudo ufw enable
		ok "Firewall rules installed"
	else
		warn "Make sure to run the following commands when installation is done:"
		echo "sudo ufw default deny incoming"
		echo "sudo ufw default allow outgoing"
		echo "sudo ufw allow http"
		echo "sudo ufw allow https"
		echo "sudo ufw allow $MAINTENANCE_SSH_PORT"
		echo "sudo ufw allow $REPO_SSH_PORT"
		echo "sudo ufw enable"
	fi
fi

header "Starting & Refreshing Services"

echo "We're pretty much ready now. At this point we're going to start the new installed services and the website and also"
echo "reload the maintenance SSH service. In case you decided to change the SSH service port then your current remote"
echo "session will be terminated. You'll have to log in again using the new maintenance port number."
echo
read -n 1 -s -r -p "Press any key to continue"
echo

info "Updating maintenance SSH service configuration"
ssh_config "Port" "$MAINTENANCE_SSH_PORT"

sudo systemctl daemon-reload

sudo service "${PHP_VERSION}-fpm" restart
sudo service phabricator start
sudo service aphlict start
sudo service ssh restart
sudo service ssh-phabricator start
sudo service nginx restart

ok "Phabricator has been successfully installed. Open https://$DOMAIN_NAME in your web browser and start phabricating"
