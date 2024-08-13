#!/bin/sh
################################################################################
# This script is work for auto deploy proxy software and start service.
# author: Charles.K
# version: v1.1.0
################################################################################

SERVER_NAME="" # server's domain name, will use to sni and request cert.
EMAIL=""  # using on request cert.

createFolders(){
	echo "Create folders which will be used."
	mkdir -p /usr/local/nginx/src /usr/local/cloudreve /usr/local/xray /var/log/xray /usr/local/certs /usr/local/proxy_scripts
}

installDependencePackage(){
	echo "Install pcre package."
	dnf install -y openssl openssl-devel pcre pcre-devel
}

addUserandGroup(){
	echo "add nginx user and group."
	groupadd www
	useradd -g www -s /sbin/nologin www
}

installNginx(){
	echo "Install nginx from source code."
	installDependencePackage
	cd /usr/local/nginx/src
	wget https://nginx.org/download/nginx-1.26.0.tar.gz
	tar xf nginx-1.26.0.tar.gz
	cd nginx-1.26.0
	addUserandGroup
	./configure --prefix=/usr/local/nginx --user=www --group=www --sbin-path=/usr/local/nginx/sbin/nginx --conf-path=/usr/local/nginx/conf/nginx.conf  --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock  --with-http_ssl_module --with-http_sub_module --with-http_gunzip_module --with-http_stub_status_module --with-pcre --with-stream --with-stream_realip_module  --with-stream_ssl_module --with-stream_ssl_preread_module --with-http_v2_module --with-http_gzip_static_module
	make && make install
	ln -s /usr/local/nginx/sbin/nginx /usr/local/sbin/nginx
	cat > /usr/lib/systemd/system/nginx.service << EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}

modifyNginxConfig(){
	echo "Modify nginx configuration."
	mkdir -p /usr/local/nginx/conf/vhost
	cat > /usr/local/nginx/conf/nginx.conf <<EOF
worker_processes  1;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
    include vhost/*.conf;
}
EOF
	cat > /usr/local/nginx/conf/vhost/http80.conf << EOF
server{
    listen 80;
    server_name $SERVER_NAME;

    error_page 403 /403.html;

    location / {
        return 403;
    }
	
    location = /403.html {
        root /usr/local/nginx/html;
    }
}
EOF
	cat > /usr/local/nginx/html/403.html << EOF
<!DOCTYPE html>
<html>
<head>
<title>Error</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Please use https.</h1>
<p>Sorry, the page only service for https, Please use https to access.</p>
</body>
</html>
EOF
	systemctl enable --now nginx
	firewall-cmd --add-service=http --permanent
	firewall-cmd --add-service=https --permanent
	firewall-cmd --reload
}

installCloudreve(){
	echo "Install cloudreve."
	cd /usr/local/cloudreve
	wget https://github.com/cloudreve/Cloudreve/releases/download/3.8.3/cloudreve_3.8.3_linux_amd64.tar.gz
	tar xf cloudreve_3.8.3_linux_amd64.tar.gz
	nohup ./cloudreve > first.log &
	sleep 10
	kill $(ps -ef | grep "cloudreve" | grep -v "grep" | awk '{ print $2 }')
	cat > /usr/lib/systemd/system/cloudreve.service << EOF
[Unit]
Description=Cloudreve
After=network.target
Wants=network.target

[Service]
WorkingDirectory=/usr/local/cloudreve
ExecStart=/usr/local/cloudreve/cloudreve
Restart=on-abnormal
RestartSec=5s
KillMode=mixed

StandardOutput=null
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --now cloudreve
	cat > /usr/local/nginx/conf/vhost/cloudreve.conf << EOF
server {
    listen 8001 proxy_protocol;
    listen 8002 http2 proxy_protocol;
  
    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-NginX-Proxy true;
        proxy_pass http://127.0.0.1:5212;
    }
}
EOF
}

installXray(){
	cd /usr/local/xray
	wget https://github.com/XTLS/Xray-core/releases/download/v1.8.16/Xray-linux-64.zip
	unzip Xray-linux-64.zip
	rm -f Xray-linux-64.zip
	ln -s /usr/local/xray/xray /usr/local/bin/xray
	cat > /usr/lib/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
	UUID=$(xray uuid)
	cat > /usr/local/xray/config.json << EOF
{
    "log": {
      "loglevel": "warning",
      "access": "/var/log/xray/access.log",
      "error": "/var/log/xray/error.log",
      "dnsLog": false
    },
    "inbounds": [
      {
        "listen": "0.0.0.0",
        "port": 443,
        "protocol": "vless",
        "settings": {
          "clients": [
            {
              "id": "$UUID",
              "flow": "xtls-rprx-vision"
            }
          ],
          "decryption": "none",
          "fallbacks": [
            {
              "dest": 8001,
              "xver": 1
            },
	    {
	      "alpn": "h2",
	      "dest": 8002,
	      "xver": 1
	    }
          ]
        },
        "streamSettings": {
          "network": "tcp",
          "security": "tls",
          "tlsSettings": {
            "rejectUnknownSni": true,
            "minVersion": "1.2",
            "certificates": [
              {
                "certificateFile": "/usr/local/certs/fullchain.cer",
                "keyFile": "/usr/local/certs/cert.key"
              }
            ]
          }
        }
      }
    ],
    "outbounds": [
      {
        "protocol": "freedom"
      }
    ]
}
EOF
	cat > /etc/logrotate.d/xray << EOF
# Xray logs
/var/log/xray/*.log {
daily
rotate 7
missingok
notifempty
dateext
copytruncate
}
EOF
	systemctl daemon-reload
	systemctl enable xray
}

setupProxy(){
	cat > /usr/local/proxy_scripts/reload-certs.sh << EOF
#!/bin/sh

systemctl restart xray
EOF
	chmod +x /usr/local/proxy_scripts/*.sh
}

installCerts(){
	echo "Install cert."
	systemctl restart nginx
	cd /root
	curl https://get.acme.sh | sh -s email=$EMAIL
	cd .acme.sh/
	./acme.sh --issue -d $SERVER_NAME --nginx /usr/local/nginx/conf/nginx.conf
	./acme.sh --install-cert -d $SERVER_NAME --key-file /usr/local/certs/cert.key --fullchain-file /usr/local/certs/fullchain.cer --reloadcmd  "sh /usr/local/proxy_scripts/reload-certs.sh"
}

downloadScript(){
	echo "Download script."
	cd /root
	wget https://lengcangkuganmian.github.io/scripts/proxy/tcp.sh
	chmod +x tcp.sh
}

main()
{
	echo "Start install trojan-go proxy server."
	createFolders
	installNginx
	modifyNginxConfig
	installCloudreve
	installXray
	setupProxy
	installCerts
	downloadScript
	echo "Install complete."
}

main
