#!/bin/sh

set -e

add_group()
{
	group=$1
	user=$2
	dir=$3

	if  ! getent group "$group" > /dev/null 2>&1; then
		addgroup -S $group; 
	fi 
	if  ! getent passwd "$user" > /dev/null 2>&1; then
		adduser -h /home/$user -g $group $user;
    	echo "$user:pass" | chpasswd
	fi
	mkdir -p $dir
	chown -R $user:$group $dir
}

user_ssh()
{
	group=$1
	user=$2
	dir=/home/$user/.ssh
	
	mkdir -p $dir
	chmod 700 $dir
	chown -R $user:$group $dir

	echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnE0KL+BPIoUGBLC88lbsb6N4jsZRqPkSYhUnmzBCiO droied@nox" > $dir/authorized_keys
	chmod 600 $dir/authorized_keys
}

config_nginx()
{
	dir=$1
	echo "Applying configuration"
	envsubst '${NGINX_PORT} ${SSL_PATH} ${NGINX_BDIR}' < /nginx.conf > /etc/nginx/nginx.conf
	if [ -f /index.html ]; then
		mv /index.html /var/www/html/
	fi
	sed -i '/^nginx:/ s#/sbin/nologin#/bin/sh#' /etc/passwd
    echo "nginx:pass" | chpasswd
	echo "Nginx config Complete"
}

config_tor()
{
	echo "Starting Tor config"
	if [ -f /torrc ]; then
		mv /torrc /etc/tor/
	fi

	tor -f /etc/tor/torrc &
	while [ ! -f /var/lib/tor/onion_service/hostname ]; do
		echo "Waiting for Tor hostname..."
		sleep 1
	done
	echo "Tor config Complete"
}

config_ssh()
{
	echo "Starting ssh config"
	if [ -f /sshd_config ]; then
		mv /sshd_config /etc/ssh/
	fi

	domain=$(cat /var/lib/tor/onion_service/hostname)
	sed -i "s|\onion|$domain|g" /etc/nginx/nginx.conf
	ssh-keygen -A
	/usr/sbin/sshd &
	echo "ssh config Complete"
}

init_nginx()
{
	dir=${NGINX_BDIR}
	add_group "nginx" "nginx" $dir
	user_ssh "nginx" "nginx"
	add_group "tor" "tor" "/var/lib/tor"
	config_nginx $dir	
	config_tor
	config_ssh
	echo "Configuration Complete! Starting Nginx..."
	domain=$(cat /var/lib/tor/onion_service/hostname)
	echo $domain 
	exec "$@"
}

if [ "$1" = "nginx" ]; then
	init_nginx "$@"
else
	exec "$@"
fi
