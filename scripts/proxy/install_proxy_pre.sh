#!/bin/sh
################################################################################
# This script is work for VPS init. now support only for almalinux9
# author: Charles.K
# version: v1.0.0
################################################################################

SSH_PORT=9528  # use ssh port what you want


turnOffSelinux(){
	echo "Turn off SElinux feature."
	sed -i 's/^SELINUX=.*/SELINUX=disabled/g' /etc/selinux/config
	setenforce 0
}

modifySSHPort(){
	echo "Modify SSH port and modify firewall rule."
	sed -i "s/^#Port.*/Port $SSH_PORT/g" /etc/ssh/sshd_config
	sed -i "s/port=\"22\"/port=\"$SSH_PORT\"/g" /usr/lib/firewalld/services/ssh.xml
}

makePackageRepoCache(){
	echo "Make dnf cache."
	dnf makecache
}

installInitTools(){
	echo "Install server init tools."
	dnf install -y vim zip unzip net-tools curl wget
}

installDevelopmentTools(){
	echo "Install Development Tools."
	dnf groupinstall -y "Development Tools"
}

downloadScript(){
	echo "Download script."
	cd /root
	wget https://lengcangkuganmian.github.io/scripts/proxy/install_proxy_main.sh
	chmod +x install_proxy_main.sh
}

initServer(){
	echo "Init Server."
	timedatectl set-timezone Asia/Shanghai
	echo "alias ll='ls -ahl'" >> /etc/profile
	source /etc/profile
	turnOffSelinux
	modifySSHPort
	makePackageRepoCache
	installInitTools
	installDevelopmentTools
}

initServer