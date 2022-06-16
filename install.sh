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
export DEBIAN_FRONTEND=noninteractive
export PKG_MANAGER=$(command -v yum || command -v apt-get)
export R=20
export C=70

error() {
    ${PRIN} "$1 ${CROSS}\n"
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

DIALOG_CONFIRM() {
    whiptail --title "Please Read Before Continue" \
        --msgbox "You need a domain that already pointing at Cloudflare.com\n\n\
This needed coz this tunnel need connect as websocket mode\n\n\
If you not pointing domain to cloudflare you can't connect with bug from cloudflare." ${R} ${C}

    if (whiptail --title "Question" --yesno "Did you already pointing domain ?" 10 40); then
        DIALOG_DOMAIN
    else
        whiptail --title "Failed" --msgbox "Please pointing domain to\n\nhttps://www.cloudflare.com/" 10 40
        exit
    fi
}

DIALOG_DOMAIN() {
    dDomain=$(whiptail --inputbox "Write Your Domain :" 10 50 "example.org" \
        3>&1 1>&2 2>&3)

    if [ $? = 0 ] ; then
        whiptail --title "Domain Name" --msgbox "Domain Used : ${DIALOG_DOMAIN}" 10 30
        export DOMAIN_ADDR=${dDOMAIN}
    else
        DIALOG_CONFIRM
    fi
}

ZEROWRT_TUNNEL() {
    whiptail --checklist --separate-output "Choose your package" ${R} ${C} 3 \
		"SSH" "include dropbear,stunnel,websocket" ON \
		"Openvpn" "Still beta"  OFF \
        "Defender" "A tool to deflate ddos" ON \
		2>tunnel.txt

    if [ $? = 0 ] ; then
        whiptail --title "Result" --msgbox "Selected Packages : \n\n$(cat tunnel.txt)" 15 30
        export DOMAIN_ADDR=${DIALOG_DOMAIN}
    else
        DIALOG_DOMAIN
    fi

    while read dTunnel ; do
        case "$dTunnel" in
            SSH)
                dropbear ; stunnel5 ; badvpn ; websocket
            ;;
            Openvpn)
                Openvpn
            ;;
            Defender)
                defender
            ;;
            *)
            ;;
        esac
    done < tunnel.txt
}

# rCloudflare() {
#     # Read domain
#     read -r -p " ${QST} Write domain : " cDOMAIN
#     # Read email
#     read -r -p " ${QST} Write email cloudflare : " cEMAIL
#     # Read api key
#     read -r -p " ${QST} Write api key cloudflare : " cKEY
#     # Read sub domain you want
#     read -r -p " ${QST} Write sub domain to create record DNS : " cSUB
# }

tools() {
    ${PRIN} " %b %s " "${INFO}" "Package Manager : ${PKG_MANAGER}"
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
    # Update
    ${PRIN} " %b %s ... \n" "${INFO}" "Updating repo"
    	${PKG_MANAGER} update -qq -y || error "Update failed !"
    ${PRIN} " %b %s " "${INFO}" "Update repo"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Upgrade
    ${PRIN} " %b %s ... \n" "${INFO}" "Upgrading packages"
    	${PKG_MANAGER upgrade -qq -y || error "Upgrade failed !"
    ${PRIN} " %b %s " "${INFO}" "Upgrade packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Install
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages"
    	${PKG_MANAGER} install net-tools iptables iptables-persistent openssl qrencode nmap bzip2 gzip coreutils screen fail2ban jq lolcat rsyslog zip unzip libxml-parser-perl bc apt-transport-https build-essential dirmngr libxml-parser-perl git -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Install packages"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
}

# cDNS() {
#     export CLOUDFLARE_URL="https://api.cloudflare.com/client/v4/zones"
#     export ZONE=$(curl -sLX GET "${CLOUDFLARE_URL}?name=${cDOMAIN}&status=active" \
#         -H "X-Auth-Email: ${cEMAIL}" \
#         -H "X-Auth-Key: ${cKEY}" \
#         -H "Content-Type: application/json" | jq -r .result[0].id)
#     export RECORD=$(curl -sLX GET "${CLOUDFLARE_URL}/${ZONE}/dns_records?name=${sub}" \
#         -H "X-Auth-Email: ${cEMAIL}" \
#         -H "X-Auth-Key: ${cKEY}" \
#         -H "Content-Type: application/json" | jq -r .result[0].id)
#     if [[ "${RECORD}" -le 10 ]]; then
#         export RECORD=$(curl -sLX POST "${CLOUDFLARE_URL}/${ZONE}/dns_records" \
#             -H "X-Auth-Email: ${cEMAIL}" \
#             -H "X-Auth-Key: ${cKEY}" \
#             -H "Content-Type: application/json" \
#             --data '{"type":"A","name":"'${cDOMAIN}'","content":"'${IP_PUBLIC}'","ttl":120,"proxied":false}' | jq -r .result.id)
#     fi
#     export RESULT=$(curl -sLX PUT "${CLOUDFLARE_URL}/${ZONE}/dns_records/${RECORD}" \
#         -H "X-Auth-Email: ${cEMAIL}" \
#         -H "X-Auth-Key: ${cKEY}" \
#         -H "Content-Type: application/json" \
#         --data '{"type":"A","name":"'${cSUB}'","content":"'${IP_PUBLIC}'","ttl":120,"proxied":false}')
# }

dropbear() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages : drobear"
    	${PKG_MANAGER} install dropbear -qq -y || error "Install the requirements package failed !"
    ${PRIN} " %b %s " "${INFO}" "Dropbear installed"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup dropbear
    ${PRIN} " %b %s ... " "${INFO}" "Setting up dropbear"
        export cDROPBEAR="/etc/default/dropbear"
        sed -i 's/NO_START=1/NO_START=0/g' ${cDROPBEAR} || error "Failed to setup dropbear config !"
        sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' ${cDROPBEAR} || error "Failed to change port dropbear !"
        # Check Dropbear extra arguments
        if ! [[ $(grep 'DROPBEAR_EXTRA_ARGS="-p 109"' /etc/default/dropbear) ]] ; then
            sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109"/g' ${cDROPBEAR} || error "Failed to change port dropbear !"
        fi
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
        sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.txt"@g' ${cDROPBEAR} || error "Failed to setup dropbear config !"
        systemctl restart dropbear || error "Failed to restart dropbear.service !"
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
}

sslh(){
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages : sslh"
    	${PKG_MANAGER} install sslh -qq -y || error "Failed to install sslh !"
    ${PRIN} " %b %s " "${INFO}" "Sslh installed"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup sslh
     ${PRIN} " %b %s ... " "${INFO}" "Setting up sslh"
    cat > /etc/default/sslh << EOF
# Default options for sslh initscript
# sourced by /etc/init.d/sslh
# Disabled by default, to force yourself
# to read the configuration:
# - /usr/share/doc/sslh/README.Debian (quick start)
# - /usr/share/doc/sslh/README, at "Configuration" section
# - sslh(8) via "man sslh" for more configuration details.
# Once configuration ready, you *must* set RUN to yes here
# and try to start sslh (standalone mode only)
RUN=yes
# binary to use: forked (sslh) or single-thread (sslh-select) version
# systemd users: don't forget to modify /lib/systemd/system/sslh.service
DAEMON=/usr/sbin/sslh
DAEMON_OPTS="--user sslh --listen 0.0.0.0:443 --ssl 127.0.0.1:777 --ssh 127.0.0.1:109 --openvpn 127.0.0.1:1194 --http 127.0.0.1:8880 --pidfile /var/run/sslh/sslh.pid -n"
EOF
    ${SLP}
	${PRIN} "%b\\n" "${TICK}"
}

acme() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages : acme.sh"
        lsof -t -i tcp:80 -s tcp:listen | xargs kill
        wget -O -  https://get.acme.sh | sh -s email=captain.parjo@gmail.com
        acme.sh --issue --standalone -d ${DOMAIN_ADDR} --force
        touch /etc/xray/
        acme.sh --installcert -d ${DOMAIN_ADDR} --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key
    ${PRIN} " %b %s " "${INFO}" "acme.sh installed"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
}

stunnel5() {
    # Install pkg
    ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages : stunnel5"
        git clone https://github.com/mtrojnar/stunnel ${HOME}/stunnel5 || error "Failed to clone stunnel5 repository !"
        cd ${HOME}/stunnel5 || error "Failed to enter work dir"
        ./configure ; make ; make install || error "Failed to install stunnel5 !"
        mkdir -p /etc/stunnel5
    ${PRIN} " %b %s " "${INFO}" "Stunnel5 installed"
    ${PRIN} "%b" "${DONE}"
    ${SLP}
	${PRIN} " %b\\n" "${TICK}"
    # Setup stunnel
    ${PRIN} " %b %s ... " "${INFO}" "Setting up stunnel5"
    # Set config
    cat > /etc/stunnel5/stunnel5.conf << EOF
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 445
connect = 127.0.0.1:109

[openssh]
accept = 777
connect = 127.0.0.1:443

[openvpn]
accept = 990
connect = 127.0.0.1:1194
EOF
    # Set init service
    cat > /etc/systemd/system/stunnel5.service << END
[Unit]
Description=Stunnel5 Service
Documentation=https://www.stunnel.org/
After=syslog.target network-online.target

[Service]
ExecStart=/usr/local/bin/stunnel5 /etc/stunnel5/stunnel5.conf
Type=forking

[Install]
WantedBy=multi-user.target
END
    cat > /etc/init.d/stunnel5 << EOL
    #! /bin/sh -e
### BEGIN INIT INFO
# Provides:          stunnel
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Should-Start:      $syslog
# Should-Stop:       $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start or stop stunnel 4.x (TLS tunnel for network daemons)
# Description:       Starts or stops all configured TLS network tunnels. Each *.conf file in
#                    /usr/local/etc/stunnel/ will spawn a separate stunnel process. The list of files
#                    can be overridden in /usr/local/etc/default/stunnel, and that same file can be used
#                    to completely disable *all* tunnels.
### END INIT INFO

. /lib/lsb/init-functions

DEFAULTPIDFILE="/var/run/stunnel.pid"
DAEMON=/usr/local/lamvpn/stunnel5
NAME=stunnel5
DESC="Stunnel5 Service"
OPTIONS=""

get_opt() {
  sed -e "s;^[[:space:]]*;;" -e "s;[[:space:]]*$;;" \
    -e "s;[[:space:]]*=[[:space:]]*;=;" "$1" |
    grep -i "^$2=" | sed -e "s;^[^=]*=;;"
}

get_pidfile() {
  local file=$1
  if [ -f $file ]; then
    CHROOT=`get_opt $file chroot`
    PIDFILE=`get_opt $file pid`
    if [ "$PIDFILE" = "" ]; then
      PIDFILE=$DEFAULTPIDFILE
    fi
    echo "$CHROOT/$PIDFILE"
  fi
}

startdaemons() {
  local res file args pidfile warn status

  if ! [ -d /var/run/stunnel ]; then
    rm -rf /var/run/stunnel
    install -d -o stunnel -g stunnel /var/run/stunnel
  fi
  if [ -n "$RLIMITS" ]; then
    ulimit $RLIMITS
  fi
  res=0
  for file in $FILES; do
    if [ -f $file ]; then
      echo -n " $file: "
      args="$file $OPTIONS"
      pidfile=`get_pidfile $file`
      if egrep -qe '^pid[[:space:]]*=' "$file"; then
        warn=''
      else
        warn=' (no pid=pidfile specified!)'
      fi
      status=0
      start_daemon -p "$pidfile" "$DAEMON" $args || status=$?
      if [ "$status" -eq 0 ]; then
        echo -n "started$warn"
      else
        echo "failed$warn"
        echo "You should check that you have specified the pid= in you configuration file"
        res=1
      fi
    fi
  done;
  echo ''
  return "$res"
}

killdaemons()
{
  local sig file pidfile status

  sig=$1
  res=0
  for file in $FILES; do
    echo -n " $file: "
    pidfile=`get_pidfile $file`
    if [ ! -e "$pidfile" ]; then
      echo -n "no pid file"
    else
      status=0
      killproc -p "$pidfile" "$DAEMON" ${sig:+"$sig"} || status=$?
      if [ "$status" -eq 0 ]; then
        echo -n 'stopped'
      else
        echo -n 'failed'
        res=1
      fi
    fi
  done
  echo ''
  return "$res"
}

querydaemons()
{
  local res file pidfile status

  res=0
  for file in $FILES; do
    echo -n " $file: "
    pidfile=`get_pidfile "$file"`
    if [ ! -e "$pidfile" ]; then
      echo -n 'no pid file'
      res=1
    else
      status=0
      pidofproc -p "$pidfile" "$DAEMON" >/dev/null || status="$?"
      if [ "$status" = 0 ]; then
        echo -n 'running'
      elif [ "$status" = 4 ]; then
        echo "cannot access the pid file $pidfile"
        res=1
      else
        echo -n 'stopped'
        res=1
      fi
    fi
  done
  echo ''
  exit "$res"
}

restartrunningdaemons()
{
  local res file pidfile status args

  res=0
  for file in $FILES; do
    echo -n " $file: "
    pidfile=`get_pidfile "$file"`
    if [ ! -e "$pidfile" ]; then
      echo -n 'no pid file'
    else
      status=0
      pidofproc -p "$pidfile" "$DAEMON" >/dev/null || status="$?"
      if [ "$status" = 0 ]; then
        echo -n 'stopping'
        killproc -p "$pidfile" "$DAEMON" "$sig" || status="$?"
        if [ "$status" -eq 0 ]; then
          echo -n ' starting'
          args="$file $OPTIONS"
          start_daemon -p "$pidfile" "$DAEMON" $args || status="$?"
          if [ "$status" -eq 0 ]; then
            echo -n ' started'
          else
            echo ' failed'
            res=1
          fi
        else
          echo -n ' failed'
          res=1
        fi
      elif [ "$status" = 4 ]; then
        echo "cannot access the pid file $pidfile"
      else
        echo -n 'stopped'
      fi
    fi
  done
  echo ''
  exit "$res"
}

if [ "x$OPTIONS" != "x" ]; then
  OPTIONS="-- $OPTIONS"
fi

# If the user want to manage a single tunnel, the conf file's name
# is in $2. Otherwise, respect /usr/local/etc/default/stunnel4 setting.
# If no setting there, use /usr/local/etc/stunnel/*.conf.
if [ -n "${2:-}" ]; then
  if [ -e "/etc/stunnel5/stunnel5.conf" ]; then
    FILES="/etc/stunnel5/stunnel5.conf"
  fi
else
  if [ -z "$FILES" ]; then
    FILES="/etc/stunnel5/*.conf"
  fi
fi

[ -x $DAEMON ] || exit 0

set -e

res=0
case "$1" in
  start)
    echo -n "Starting $DESC:"
    startdaemons
    res=$?
    ;;
  stop)
    echo -n "Stopping $DESC:"
    killdaemons
    res=$?
    ;;
  reopen-logs)
    echo -n "Reopening log files $DESC:"
    killdaemons USR1
    res=$?
    ;;
  force-reload|reload)
    echo -n "Reloading configuration $DESC:"
    killdaemons HUP
    res=$?
    ;;
  restart)
    echo -n "Restarting $DESC:"
    killdaemons && startdaemons
    res=$?
    ;;
  try-restart)
    echo -n "Restarting $DESC if running:"
    restartrunningdaemons
    res=$?
    ;;
  status)
    echo -n "$DESC status:"
    querydaemons
    res=$?
    ;;
  *)
    N=/etc/init.d/$NAME
    echo "Usage: $N {start|stop|status|reload|reopen-logs|restart|try-restart} [<stunnel instance>]" >&2
    res=1
    ;;
esac

exit "$res"
EOL
    # run + onboot via init.d
    systemctl daemon-reload ; /etc/init.d/stunnel5 enable ; /etc/init.d/stunnel5 restart
    ${SLP}
 	${PRIN} "%b\\n" "${TICK}"
}

# stunnel() {
#     # Install pkg
#     ${PRIN} " %b %s ... \n" "${INFO}" "Installing packages : stunnel"
#     	${PKG_MANAGER} install stunnel4 -qq -y || error "Install the requirements package failed !"
#     ${PRIN} " %b %s " "${INFO}" "Stunnel installed"
#     ${PRIN} "%b" "${DONE}"
#     ${SLP}
# 	${PRIN} " %b\\n" "${TICK}"
#     # Setup stunnel
#     ${PRIN} " %b %s ... " "${INFO}" "Setting up stunnel"
#         export aC=ID
#         export aST=Indonesia
#         export aL=Semarang
#         export aO=Zeroland
#         export aOU=Zero Tunnel
#         export aCN=Kadal
#         export aEM=zeroland.tunnel@gmail.com
#         cat > /etc/stunnel/stunnel.conf << EOF
# cert = /etc/stunnel/stunnel.pem
# client = no
# socket = a:SO_REUSEADDR=1
# socket = l:TCP_NODELAY=1
# socket = r:TCP_NODELAY=1

# [dropbear]
# accept = 443
# connect = 127.0.0.1:445

# [dropbear1]
# accept = 777
# connect = 127.0.0.1:22

# [WebsocketDropbear]
# accept = 2021
# connect = 127.0.0.1:445

# [WebsocketStunnel]
# accept = 5052
# connect = 127.0.0.1:143

# # [openvpn]
# # accept = 443
# # connect = 127.0.0.1:1194
# EOF
#         openssl genrsa -out key.pem 2048 || error "Failed to generate openssl cert !"
#         openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
#         -subj "/C=${aC}/ST=${aST}/L=${aL}/O=${aO}/OU=${aOU}/CN=${aCN}/emailAddress=${aEM}" || error "Failed to generate openssl cert !"
#         cat key.pem cert.pem >> /etc/stunnel/stunnel.pem || error "Failed to copy openssl cert !"
#         #sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4 || error "Failed to set stunnel 1"
#         systemctl restart stunnel4 || error "Failed to restart stunnel4.service !"
#     ${SLP}
# 	${PRIN} "%b\\n" "${TICK}"
# }

badvpn() {
    # fix instal + repo
    export uBADVPN="https://github.com/jakues/zeroland/releases/download/badvpn/badvpn-udpgw64"
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
    	${PKG_MANAGER} install openvpn easy-rsa -qq -y || error "Install the requirements package failed !"
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
remote iPUBLIC 990
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
        # configure file for client 990 ssl
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
    	${PKG_MANAGER} install squid3 -qq -y || error "Install the requirements package failed !"
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

websocket() {
    # Install websocket dropbear
    cat > /etc/systemd/system/ws-dropbear.service << EOL
[Unit]
Description=Websocket Dropbear Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/ws-dropbear 8880
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL
    cat > /usr/local/bin/ws-dropbear << EOF
#!/usr/bin/python
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = sys.argv[1]

# Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:109'
RESPONSE = 'HTTP/1.1 101 <b><font color="green">Switching Protocols</font></b>\r\n\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

#######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()
EOF
    # Install websocket stunnel
    cat > /etc/systemd/system/ws-stunnel.service << EOL
[Unit]
Description=Websocket Stunnel Service
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/ws-stunnel 443
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL
    cat > /usr/local/bin/ws-stunnel << EOF
#!/usr/bin/python
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = sys.argv[1]

# Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:443'
RESPONSE = 'HTTP/1.1 101 <b><font color="green">Switching Protocols</font></b>\r\n\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

#######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()
EOF
    # Install websocket openssh
    cat > /etc/systemd/system/ws-openvpn.service << EOL
[Unit]
Description=Websocket OpenVPN Service
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/ws-openvpn 2086

[Install]
WantedBy=multi-user.target
EOL
    cat > /usr/local/bin/ws-openvpn << EOF
#!/usr/bin/python
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = sys.argv[1]

# Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:1194'
RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\n\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

#######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()
EOF
    # Reload the websocket service
    systemctl daemon-reload
    # Dropbear
    systemctl enable ws-dropbear.service
    systemctl restart ws-dropbear.service
    # Stunnel
    systemctl enable ws-stunnel.service
    systemctl restart ws-stunnel.service
    # OpenVPN
    systemctl enable ws-openvpn.service
    systemctl restart ws-openvpn.service
}

# xray() {
#     # Install pkg
#     ${PRIN} " %b %s ... \n" "${INFO}" "Installing requirements packages"
#     	${PKG_MANAGER} install bash-completion chrony ntpdate socat  gnupg gnupg2 gnupg1 dnsutils -qq -y || error "Install the requirements package failed !"
#     ${PRIN} " %b %s " "${INFO}" "Install packages"
#     ${PRIN} "%b" "${DONE}"
#     ${SLP}
# 	${PRIN} " %b\\n" "${TICK}"
# }

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
    # ${PRIN} " %b %s ... \n" "${INFO}" "Configuring iptables"
    # iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    # iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    # iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    # iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    # iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    # iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    # iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    # iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    # iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    # iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    # iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    # iptables-save > /etc/iptables.up.rules
    # iptables-restore -t < /etc/iptables.up.rules
    # netfilter-persistent save
    # netfilter-persistent reload
    # ${PRIN} " %b %s " "${INFO}" "Configure iptables"
    # ${PRIN} "%b" "${DONE}"
    # ${SLP}
	# ${PRIN} " %b\\n" "${TICK}"
}

main() {
    soedo
    inet
    tools
    DIALOG_CONFIRM
    ZEROWRT_TUNNEL
}

main