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

badvpn_start() {
    badvpn --listen-addr 127.0.0.1:7300 --max-clients 300 --loglevel 1 || error "Failed to start badvpn !"
}

badvpn_stop() {
    killall badvpn || error "Failed to stop badvpn or service not running !"
}

case "$1" in
    --badvpn-start)
        inet ; badvpn_start
    ;;
    --badvpn_stop)
        inet ; badvpn_stop
    ;;
    --badvpn_restart)
        inet ; badvpn_stop ; badvpn_start
esac