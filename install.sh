#!/bin/bash

export PRIN="printf"
export ECMD="echo -e"
export CR='\e[0m'
export COL_LIGHT_GREEN='\e[1;32m'
export COL_LIGHT_RED='\e[1;31m'
export TICK="[${COL_LIGHT_GREEN}✓${CR}]"
export CROSS="[${COL_LIGHT_RED}✗${CR}]"
export INFO="[i]"
export QST="[?]"
export DONE="${COL_LIGHT_GREEN} done !${CR}"
export SLP="sleep 0.69s"
export IP_PUBLIC=$(wget -T 10 -t 1 -4qO- http://ip1.dynupdate.no-ip.com/)

error() {
    ${PRIN} "$1 ${CROSS}"
    exit
}

soedo() {
	# Need run as root user
	${PRIN} " %b %s ... " "${INFO}" "Detect root"
	if [[ $(id -u) -ne 0 ]] ; then
		${SLP}
		${PRIN} "%b\\n" "${CROSS}"
		error "This script need run as root !"
	fi
	${SLP}
	${PRIN} "%b\\n" "${TICK}"
}

inet() {
	${PRIN} " %b %s ... " "${INFO}" "Detect connections"
	if [[ $(ping -q -c 1 -W 1 8.8.8.8) ]] ; then 
		${SLP}
		${PRIN} "%b\\n" "${TICK}"
	else 
		${SLP}
		${PRIN} "%b\\n" "${CROSS}"
		error "No internet connections !"
	fi
}

rCloudflare() {
    # Read domain
    read -r -p " ${QST} Write domain : " cDOMAIN
    # Read email
    read -r -p " ${QST} Write email cloudflare : " cEMAIL
    # Read api key
    read -r -p " ${QST} Write api key cloudflare : " cKEY
    # Read sub domain you want
    read -r -p " ${QST} Write sub domain to create record DNS : " cSUB
}

tools_deb() {
    ${PRIN} " %b %s " "${INFO}" "Package Manager : apt-get"
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
    # Update
    ${PRIN} " %b %s ... \n" "${INFO}" "Updating repo"
    	apt-get update -qq -y || error "Update failed !"
    ${PRIN} " %b %s " "${INFO}" "Update repo"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Upgrade
    ${PRIN} " %b %s ... \n" "${INFO}" "Upgrading packages"
    	apt-get upgrade -qq -y || error "Upgrade failed !"
    ${PRIN} " %b %s " "${INFO}" "Upgrade packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Install
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages"
    	apt-get install net-tools iptables iptables-persistent openssl qrencode nmap bzip2 gzip coreutils screen fail2ban jq lolcat rsyslog zip unzip libxml-parser-perl bc apt-transport-https build-essential dirmngr libxml-parser-perl git -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Install packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
}

cDNS() {
    export CLOUDFLARE_URL="https://api.cloudflare.com/client/v4/zones"
    export ZONE=$(curl -sLX GET "${CLOUDFLARE_URL}?name=${cDOMAIN}&status=active" \
        -H "X-Auth-Email: ${cEMAIL}" \
        -H "X-Auth-Key: ${cKEY}" \
        -H "Content-Type: application/json" | jq -r .result[0].id)
    export RECORD=$(curl -sLX GET "${CLOUDFLARE_URL}/${ZONE}/dns_records?name=${sub}" \
        -H "X-Auth-Email: ${cEMAIL}" \
        -H "X-Auth-Key: ${cKEY}" \
        -H "Content-Type: application/json" | jq -r .result[0].id)
    if [[ "${RECORD}" -le 10 ]]; then
        export RECORD=$(curl -sLX POST "${CLOUDFLARE_URL}/${ZONE}/dns_records" \
            -H "X-Auth-Email: ${cEMAIL}" \
            -H "X-Auth-Key: ${cKEY}" \
            -H "Content-Type: application/json" \
            --data '{"type":"A","name":"'${cDOMAIN}'","content":"'${IP_PUBLIC}'","ttl":120,"proxied":false}' | jq -r .result.id)
    fi
    export RESULT=$(curl -sLX PUT "${CLOUDFLARE_URL}/${ZONE}/dns_records/${RECORD}" \
        -H "X-Auth-Email: ${cEMAIL}" \
        -H "X-Auth-Key: ${cKEY}" \
        -H "Content-Type: application/json" \
        --data '{"type":"A","name":"'${cSUB}'","content":"'${IP_PUBLIC}'","ttl":120,"proxied":false}')
}

dropbear() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages"
    	apt-get install dropbear -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Install packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup dropbear
    ${PRIN} " %b %s ... " "${INFO}" "Setting up dropbear"
        export cDROPBEAR="/etc/default/dropbear"
        sed -i 's/NO_START=1/NO_START=0/g' ${cDROPBEAR} || error "Failed to setup dropbear config !"
        sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' ${cDROPBEAR} || error "Failed to change port dropbear !"
        sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 445"/g' ${cDROPBEAR} || error "Failed to change port dropbear !"
        ${ECMD} "/bin/false" >> /etc/shells || error "Failed to setup dropbear !"
        ${ECMD} "/usr/sbin/nologin" >> /etc/shells || error "Failed to setup dropbear !"
        cat > /etc/banner.txt << EOF 
<center><font color="#ffa089">
──────────────────────<br>
</font><font color="#008080">
🖐 IF YOU USE THIS SERVICE 🖐<br>
🙏 PLEASE READ THIS TERM 🙏<br>
<font color="#ffa089">
──────────────────────<br>
</font>
⛔️ NO 𝙳𝙳𝙾𝚂<br>
⛔️ NO 𝙲𝙰𝚁𝙳𝙸𝙽𝙶<br>
⛔️ NO 𝚃𝙾𝚁𝚁𝙴𝙽𝚃<br>
⛔️ NO 𝙷𝙰𝙲𝙺𝙸𝙽𝙶<br>
⛔️ NO 𝚂𝙿𝙰𝙼<br>
⛔️ MULTILOGIN MAX 2<br>
<font color="#ffa089">
──────────────────────<br>
</font>
📞 Regards : t.me/pethot 📞<br>
<font color="#ffa089">
──────────────────────<br>
</font></center>
EOF
        sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="/etc/banner.txt"/g' /etc/default/dropbear || error "Failed to setup dropbear config !"
        systemctl restart dropbear || error "Failed to restart dropbear.service !"
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
}

stunnel() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages"
    	apt-get install stunnel4 -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Install packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup stunnel
    ${PRIN} " %b %s ... " "${INFO}" "Setting up stunnel"
        export aC=ID
        export aST=Indonesia
        export aL=Semarang
        export aO=Zeroland
        export aOU=Zero Tunnel
        export aCN=Kadal
        export aEM=zeroland.tunnel@gmail.com
        cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:445

[dropbear2]
accept = 777
connect = 127.0.0.1:22

[websocketpython]
accept = 2021
connect = 127.0.0.1:445

[websocket1]
accept = 5052
connect = 127.0.0.1:143

[openvpn]
accept = 443
connect = 127.0.0.1:1194
EOF
        openssl genrsa -out key.pem 2048 || error "Failed to generate openssl cert !"
        openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
        -subj "/C=${aC}/ST=${aST}/L=${aL}/O=${aO}/OU=${aOU}/CN=${aCN}/emailAddress=${aEM}" || error "Failed to generate openssl cert !"
        cat key.pem cert.pem >> /etc/stunnel/stunnel.pem || error "Failed to copy openssl cert !"
        sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4 || error "Failed to set stunnel 1"
        systemctl restart stunnel4 || error "Failed to restart stunnel4.service !"
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
}

badvpn() {
    # fix instal + repo
    export uBADVPN="https://github.com//raw/main/badvpn-udpgw64"
    wget -q -O /usr/bin/badvpn ${uBADVPN}
    chmod +x /usr/bin/badvpn
    cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description = BadVPN daemon

[Service]
Type = simple
RemainAfterExit=yes
ExecStart = /usr/bin/zero --badvpn-start
ExecStop = /usr/bin/zero --badvpn-stop
ExecReload = /usr/bin/zero --badvpn-restart

[Install]
WantedBy = multi-user.target
EOF
    # run + onboot via systemd
    systemctl daemon-reload ; systemctl enable badvpn ; systemctl start badvpn
}

openvpn() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages"
    	apt-get install openvpn easy-rsa -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Install packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup stunnel
    ${PRIN} " %b %s ... " "${INFO}" "Setting openvpn"
        export EASY_RSA="${EASY_RSA:-.}"
        export cCONF_tcp="/etc/openvpn/client-tcp-1194.ovpn"
        export cCONF_udp="/etc/openvpn/client-udp-2211.conf"
        export cCONF_ssl="/etc/openvpn/client-tcp-ssl.ovpn"
        cp -r /usr/share/easy-rsa/ /etc/openvpn || error "Failed to copy easy-rsa !"
        mkdir -p /etc/openvpn/easy-rsa/keys || error "Failed to make dircetory !"
        cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars || error "Failed to copy easy-rsa env !"
        openssl dhparam -out /etc/openvpn/dh2048.pem 2048 || error "Failed to generate openssl cert !"
        cd /etc/openvpn/easy-rsa || error "Failed to change directory !"
        cp openssl-1.0.0.cnf openssl.cnf || error "Failed to copy openssl cert !"
        . ./vars || error "Failed to set var !"
        ./clean-all || error "Failed to clean up !"
        "${EASY_RSA}/pkitool" --initca $* || error "Failed to generate easy-rsa: initca !"
        "${EASY_RSA}/pkitool" --server server || error "Failed to generate easy-rsa: server !"
        "${EASY_RSA}/pkitool" client || error "Failed to generate easy-rsa: client !"
        cd ${HOME}
        cp /etc/openvpn/easy-rsa/keys/server.crt /etc/openvpn/server.crt || error "Failed to copy easy-rsa: server.crt !"
        cp /etc/openvpn/easy-rsa/keys/server.key /etc/openvpn/server.key || error "Failed to copy easy-rsa: server.key !"
        cp /etc/openvpn/easy-rsa/keys/ca.crt /etc/openvpn/ca.crt || error "Failed to copy easy-rsa: ca.crt !"
        chmod +x /etc/openvpn/ca.crt || error "Failed to change permission: ca.crt !"
        cat > /etc/openvpn/server-tcp-1194.conf << EOF
port 1194
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
server 10.6.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 5 30
comp-lzo
persist-key
persist-tun
status server-tcp-1194.log
verb 3
EOF
        cat > /etc/openvpn/server-udp-2211.conf << EOF
port 2211
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
server 10.7.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 5 30
comp-lzo
persist-key
persist-tun
status server-udp-2200.log
verb 3
EOF
        mkdir -p /usr/lib/openvpn/ || error "Failed to make directory !"
        cp /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so || error "Failed to copy lib: openvpn-plugin-auth-pam.so !"
        sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn || error "Failed to set openvpn autostart all !"
        systemctl restart openvpn || error "Failed to restart openvpn !"
        echo 1 > /proc/sys/net/ipv4/ip_forward || error "Failed to enable ipv4 forward !"
        sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf || error "Failed to enable ipv4 forward !"
        cat > ${cCONF_tcp} << EOF
client
dev tun
proto tcp
remote iPUBLIC 1194
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
EOF
        cat > ${cCONF_udp} << EOF
client
dev tun
proto udp
remote iPUBLIC 2211
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
EOF
        cat > ${cCONF_ssl} << EOF
client
dev tun
proto tcp
remote iPUBLIC 442
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
EOF
        # configure file for client 1194 tcp
        sed -i 's/iPUBLIC/${IP_PUBLIC}/g' ${cCONF_tcp}
        ${ECMD} '<ca>' >> ${cCONF_tcp}
        cat /etc/openvpn/ca.crt >> ${cCONF_tcp}
        ${ECMD} '</ca>' >> ${cCONF_tcp}
        # configure file for client 2211 udp
        sed -i 's/iPUBLIC/${IP_PUBLIC}/g' ${cCONF_udp}
        ${ECMD} '<ca>' >> ${cCONF_udp}
        cat /etc/openvpn/ca.crt >> ${cCONF_udp}
        ${ECMD} '</ca>' >> ${cCONF_udp}
        # configure file for client 4422 ssl
        sed -i 's/iPUBLIC/${IP_PUBLIC}/g' ${cCONF_ssl}
        ${ECMD} '<ca>' >> ${cCONF_ssl}
        cat /etc/openvpn/ca.crt >> ${cCONF_ssl}
        ${ECMD} '</ca>' >> ${cCONF_ssl}
        # configure firewall
        export IFACE=$(ip -o -4 route show to default | awk '{print $5}')
        iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o ${IFACE} -j MASQUERADE
        iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o ${IFACE} -j MASQUERADE
        iptables-save > /etc/iptables.up.rules
        iptables-restore -t < /etc/iptables.up.rules
        netfilter-persistent save
        netfilter-persistent reload
        cat > /etc/network/if-up.d/iptables << EOF
iptables-restore < /etc/iptables.up.rules
iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o ${IFACE} -j SNAT --to iPUBLIC
iptables -t nat -A POSTROUTING -s 10.7.0.0/24 -o ${IFACE} -j SNAT --to iPUBLIC
EOF
        sed -i 's/iPUBLIC/${IP_PUBLIC}/g' /etc/network/if-up.d/iptables
        chmod +x /etc/network/if-up.d/iptables
        systemctl enable openvpn
        systemctl restart openvpn
}

squid() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages"
    	apt-get install squid3 -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Install packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup squid proxy
    ${PRIN} " %b %s ... " "${INFO}" "Setting squid proxy"
        export SQUID_CONF="/etc/squid/squid.conf"
        cat ${SQUID_CONF} << EOF
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 442
acl SSL_ports port 1-65535
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 143
acl Safe_ports port 109
acl Safe_ports port 500
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 69-100
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst iPUBLIC
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 8000
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname zeroland
EOF
    sed -i 's/iPUBLIC/${IP_PUBLIC}/g' ${SQUID_CONF}
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
}

defender() {
    export dir_DDOS="/usr/local/ddos"
    if [ -d '${dir_DDOS}' ]; then
        ${PRIN} "\n %b %s " "${INFO}" "Detect ddos deflate"
        ${SLP}
        ${PRIN} "%b\\n" "${TICK}"
    else
        ${PRIN} " %b %s ... " "${INFO}" "Installing ddos deflate"
	    mkdir -p ${dir_DDOS}
        wget  -e robots=off -r -k -q -nv -nH -l inf -R jpg,jpeg,gif,png,tif --reject-regex '(.*)\?(.*)'  --no-parent 'http://www.inetbase.com/scripts/ddos/' -P ${dir_DDOS}
        chmod +x ${dir_DDOS}/scripts/ddos/ddos.sh
        ${dir_DDOS}/scripts/ddos/ddos.sh --cron > /dev/null 2>&1
        ${SLP}
	    ${PRIN} "%b\\n" "${TICK}"
    fi
    ${PRIN} " %b %s ... \n" "${INFO}" "Configuring iptables"
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload
    ${PRIN} " %b %s " "${INFO}" "Configure iptables"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
}