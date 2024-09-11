#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#

set -e
export LC_ALL=C

_command() {
	hash "$1" >/dev/null 2>&1
}

_command command || command() {
	last=""
	eval last="\$$#"
	_command "$last"
}

command -v readlink >/dev/null 2>&1 || readlink() {
	last=""
	eval last="\$$#"
	cd "$(dirname "$last")" || return 1
	printf "%s/%s\n" "$(pwd)" "$(basename "$last")"
}

command -v id >/dev/null 2>&1 || id() {
	grep "$(whoami)" /etc/passwd | awk -F ':' '{print $3}'
}

SELF="$(readlink -f "$0")"
export PATH="${SELF%/*}:$PATH"

WG_CONFIG=""
INTERFACE=""
ADDRESSES=""
MTU=""
DNS=""
DNS_SEARCH=""
TABLE=""
PRE_UP=""
POST_UP=""
PRE_DOWN=""
POST_DOWN=""
SAVE_CONFIG=0
CONFIG_FILE=""
PROGRAM="${0##*/}"
ARGS="$*"
N='
'

cmd() {
	echo "[#] $*" >&2
	"$@"
}

die() {
	echo "$PROGRAM: $*" >&2
	exit 1
}

parse_options() {
	interface_section=0
	CONFIG_FILE="$1"
	echo "$CONFIG_FILE" | grep -E -q "^[a-zA-Z0-9_=+.-]{1,15}$" && CONFIG_FILE="/etc/wireguard/$CONFIG_FILE.conf"
	[ -e "$CONFIG_FILE" ] || die "\`$CONFIG_FILE' does not exist"
	echo "$CONFIG_FILE" | grep -E -q "(^|/)([a-zA-Z0-9_=+.-]{1,15})\.conf$" || \
		die "The config file must be a valid interface name, followed by .conf"
	CONFIG_FILE="$(readlink -f "$CONFIG_FILE")"
	[ $(($(stat -c '0%#a' "$CONFIG_FILE") & $(stat -c '0%#a' "${CONFIG_FILE%/*}") & 0007)) -eq 0 ] || \
		echo "Warning: \`$CONFIG_FILE' is world accessible" >&2
	INTERFACE=$(basename -s ".conf" "$CONFIG_FILE")

	while IFS= read -r line || [ -n "$line" ]; do
		stripped="${line%%\#*}"
		key="${stripped%%=*}"
		key="${key#"${key%%[![:space:]]*}"}"
		key="${key%"${key##*[![:space:]]}"}"
		value="${stripped#*=}"
		value="${value#"${value%%[![:space:]]*}"}"
		value="${value%"${value##*[![:space:]]}"}"
		case "$key" in
			"[Interface]") interface_section=1 ;;
			"["*) interface_section=0 ;;
		esac

		if [ "$interface_section" -eq 1 ]; then
			case "$key" in
				Address) ADDRESSES="${ADDRESSES}${N}${value}"; continue ;;
				MTU) MTU="$value"; continue ;;
				DNS)
					for dns in $(echo "$value" | sed -E "s/,/ /" ); do
					if echo "$dns" | grep -E -q "(^[0-9.]+$)|(^.*:.*$)"; then
						DNS="${DNS}${dns}${N}"
					else
						DNS_SEARCH="${DNS_SEARCH}${dns}${N}"
					fi
				done; continue ;;
				Table) TABLE="$value"; continue ;;
				PreUp) PRE_UP="$PRE_UP $value"; continue ;;
				PreDown) PRE_DOWN="$PRE_DOWN $value"; continue ;;
				PostUp) POST_UP="$POST_UP $value"; continue ;;
				PostDown) POST_DOWN="$POST_DOWN $value"; continue ;;
				SaveConfig) read_bool SAVE_CONFIG "$value"; continue ;;
			esac
		fi
		WG_CONFIG="${WG_CONFIG}${line}${N}"
	done < "$CONFIG_FILE"
}

read_bool() {
	case "$2" in
	true) eval "$1=1" ;;
	false) eval "$1=0" ;;
	*) die "\`$2' is neither true nor false" ;;
	esac
}

auto_su() {
	[ "$(id -u)" -eq 0 ] || \
		exec sudo -p "$PROGRAM must be run as root. Please enter the password for %u to continue: " -- "$SELF" $ARGS
}

add_if() {
	if ! cmd ip link add "$INTERFACE" type wireguard; then
		ret=$?
		wg_impl="$WG_QUICK_USERSPACE_IMPLEMENTATION"
		[ -z "$wg_impl" ] && wg_impl="wireguard-go"
		[ -e "/sys/module/wireguard" ] || ! command -v "$wg_impl" >/dev/null && exit $ret
		echo "[!] Missing WireGuard kernel module. Falling back to slow userspace implementation." >&2
		cmd "$wg_impl" "$INTERFACE"
	fi
}

del_if() {
	[ "$HAVE_SET_DNS" -eq 0 ] || unset_dns
	[ "$HAVE_SET_FIREWALL" -eq 0 ] || remove_firewall
	if [ -z "$TABLE" ] || [ "$TABLE" = auto ] && table="$(get_fwmark)" && \
		wg show "$INTERFACE" allowed-ips | grep -E -q "/0(\ |$'\n'|$)" ; then
		for proto in "-4" "-6"; do
			while ip "$proto" rule show 2>/dev/null | \
				grep -E -q ".*lookup $table.*" ; do
				cmd ip "$proto" rule delete table "$table"
			done
			while ip "$proto" rule show 2>/dev/null | \
				grep -E -q ".*from all lookup main suppress_prefixlength 0.*" ; do
				cmd ip "$proto" rule delete table main suppress_prefixlength 0
			done
		done
	fi
	cmd ip link delete dev "$INTERFACE"
}

add_addr() {
	proto="-4"
	echo "$1" | grep -q ".*:.*" && proto="-6"
	cmd ip "$proto" address add "$1" dev "$INTERFACE"
}

set_mtu_up() {
	mtu=0
	endpoint=""
	output=""

	if [ -n "$MTU" ]; then
		cmd ip link set mtu "$MTU" up dev "$INTERFACE"
		return
	fi

	for endpoint in $(wg show "$INTERFACE" endpoints) ; do
		remote_ip="$(echo "$endpoint" | sed -E -n "s/^\[?([a-z0-9:.]+)\]?:[0-9]+$/\1/p")"
		[ -n "$remote_ip" ] || continue

		output=$(ip route get "$remote_ip" 2>/dev/null || true)
		if echo "$output" | grep -q "mtu [0-9]+"; then
			new_mtu="$(echo "$output" | sed -E -n "s/.*mtu ([0-9]+).*/\1/p")"
		elif echo "$output" | grep -r -q "dev [^ ]+"; then
			dev=$(echo "$output" | sed -E -n "s/.*dev ([^ ]+).*/\1/p")
			new_mtu=$(ip link show dev "$dev" | sed -E -n "s/.*mtu ([0-9]+).*/\1/p")
		fi
		[ -n "$new_mtu" ] && [ "$new_mtu" -gt "$mtu" ] && mtu="$new_mtu"
	done

	if [ "$mtu" -eq 0 ]; then
		output=$(ip route show default 2>/dev/null || true)
		if echo "$output" | grep -E -q "mtu [0-9]+"; then
			mtu=$(echo "$output" | sed -E -n "s/.*mtu ([0-9]+).*/\1/p")
		elif echo "$output" | grep -E -q "dev [^ ]+"; then
			dev=$(echo "$output" | sed -E -n "s/.*dev ([^ ]+).*/\1/p")
			mtu=$(ip link show dev "$dev" | sed -E -n "s/.*mtu ([0-9]+).*/\1/p")
		fi
	fi

	[ "$mtu" -gt 0 ] || mtu=1500
	cmd ip link set mtu $((mtu - 80)) up dev "$INTERFACE"
}

HAVE_SET_DNS=0
DNS_SECTION_START=""
DNS_SECTION_END=""
set_dns() {
	[ -n "$DNS" ] || return 0
	DNS_SECTION_START="# ${INTERFACE}'s servers begin"
	DNS_SECTION_END="# end generated by ${PROGRAM}"
	{
		printf "%s\n" "$DNS_SECTION_START"
		for dns in $DNS ; do
			printf "nameserver %s\n" "$dns"
		done
		[ -z "$DNS_SEARCH" ] || printf "search %s\n" "$DNS_SEARCH"
		printf "%s\n" "$DNS_SECTION_END"
	} >>"/etc/resolv.conf"
	HAVE_SET_DNS=1
}

unset_dns() {
	[ -n "$DNS" ] || return 0
	sed -E -i "/^$DNS_SECTION_START/,/^$DNS_SECTION_END/d" "/etc/resolv.conf"
}

get_dns() {
	 awk -v start="$DNS_SECTION_START" -v end="$DNS_SECTION_END" \
	 	'$0~start{flag=1; next} $0~end{flag=0} flag' "/etc/resolv.conf"
}

add_route() {
	proto="-4"
	echo "$1" | grep ".*:.*" && proto="-6"
	[ "$TABLE" != off ] || return 0

	if [ -n "$TABLE" ] && [ "$TABLE" != auto ]; then
		cmd ip $proto route add "$1" dev "$INTERFACE" table "$TABLE"
	elif echo "$1" | grep ".*/0" ; then
		add_default "$1"
	else
		[ -n "$(ip $proto route show dev "$INTERFACE" match "$1" 2>/dev/null)" ] || \
			cmd ip $proto route add "$1" dev "$INTERFACE"
	fi
}

get_fwmark() {
	fwmark="$(wg show "$INTERFACE" fwmark)" || return 1
	[ -n "$fwmark" ] && [ "$fwmark" != off ] || return 1
	printf "%d" "$fwmark"
	return 0
}

remove_firewall() {
	if command -v nft >/dev/null 2>&1; then
		nftcmd=""
		while read -r table; do
			echo "$table" | grep -E -q ".* wg-quick-$INTERFACE" && \
				nftcmd="${nftcmd}delete ${table}${N}"
		done <<-_EOF
		$(nft list tables 2>/dev/null)
		_EOF
		[ -n "$nftcmd" ] && cmd nft "$nftcmd"
	fi

	if command -v iptables >/dev/null 2>&1; then
		for iptables in iptables ip6tables; do
			restore=""
			found=0
			while read -r line; do
				case "$line" in
					"COMMIT" | "-A "*"-m comment --comment \"wg-quick(8) rule for $INTERFACE\""* )
						line="$(echo "$line" | sed -E -n "s/^-A/-D/p")"
						[ -n "$line" ] || continue
						restore="${restore}${line}${N}"
						found=1
						;;
					*) ;;
				esac
			done <<-_EOF
			$($iptables-save 2>/dev/null)"
			_EOF
			[ "$found" -ne 0 ] && echo "$restore" | cmd $iptables-restore -n
		done
	fi
}

HAVE_SET_FIREWALL=0
add_default() {
	if ! table="$(get_fwmark)"; then
		table=51820
		while [ -n "$(ip -4 route show table $table 2>/dev/null)" ] || \
			[ -n "$(ip -6 route show table $table 2>/dev/null)" ]; do
			table=$((table+1))
		done
		cmd wg set "$INTERFACE" fwmark $table
	fi

	proto="-4" iptables="iptables" pf="ip"
	echo "$1" | grep ".*:.*" && proto="-6" iptables="ip6tables" pf="ip6"
	cmd ip $proto rule add not fwmark "$table" table "$table"
	cmd ip $proto rule add table main suppress_prefixlength 0
	cmd ip $proto route add "$1" dev "$INTERFACE" table "$table"

	marker="-m comment --comment \"wg-quick(8) rule for $INTERFACE\""
	restore="*raw${N}"
	nftable="wg-quick-$INTERFACE"
	nftcmd="${nftcmd}add table ${pf} ${nftable}${N}"
	nftcmd="${nftcmd}add chain ${pf} ${nftable} preraw { type filter hook prerouting priority -300; }${N}"
	nftcmd="${nftcmd}add chain ${pf} ${nftable} premangle { type filter hook prerouting priority -150; }${N}"
	nftcmd="${nftcmd}add chain ${pf} ${nftable} postmangle { type filter hook postrouting priority -150; }${N}"
	while read -r line || [ -n "$line" ]; do
		addr="$(echo "$line" | sed -E -n "s/.*inet6?\ ([0-9a-f:.]+)\/[0-9]+.*/\1/p")"
		[ -n "$addr" ] || continue
		restore="${restore}-I PREROUTING ! -i ${INTERFACE} -d ${addr} -m addrtype ! --src-type LOCAL -j DROP ${marker}${N}"
		nftcmd="${nftcmd}add rule ${pf} ${nftable} preraw iifname != \"${INTERFACE}\" ${pf} daddr ${addr} fib saddr type != local drop${N}"
	done <<-_EOF
	$(ip -o $proto addr show dev "$INTERFACE" 2>/dev/null)
	_EOF
	restore="COMMIT${N}*mangle${N}-I POSTROUTING -m mark --mark ${table} -p udp -j CONNMARK --save-mark ${marker}${N}-I PREROUTING -p udp -j CONNMARK --restore-mark ${marker}${N}COMMIT${N}"
	nftcmd="${nftcmd}add rule ${pf} ${nftable} postmangle meta l4proto udp mark ${table} ct mark set mark ${N}"
	nftcmd="${nftcmd}add rule ${pf} ${nftable} premangle meta l4proto udp meta mark set ct mark ${N}"

	[ "$proto" = "-4" ] && cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1
	if command -v nft >/dev/null; then
		cmd nft "$nftcmd"
	else
		cmd $iptables-restore -n "$restore"
	fi
	HAVE_SET_FIREWALL=1
	return 0
}

set_config() {
	tmp="/tmp/$PROGRAM-wg-cfg-$(id -u)-$$"
	trap 'rm -f "$tmp"' INT TERM EXIT HUP
	echo "$WG_CONFIG" >"$tmp"
	sync "$tmp"
	cmd wg setconf "$INTERFACE" "$tmp"
	trap - INT TERM EXIT HUP
}

save_config() {
	cmd=""
	new_config="[Interface]${N}"

	for address in $(ip -all -brief address show dev "$INTERFACE" | sed -E -n "s/^$INTERFACE\ +\ [A-Z]+\ +(.+)$/\1/p"); do
		new_config="${new_config}Address = ${address}${N}"
	done

	while read -r address; do
		dns="$(echo "$address" | sed -E -n "s/^nameserver\ ([a-zA-Z0-9_=+:%.-]+)$/\1/p")"
		[ -n "$dns" ] && new_config="${new_config}DNS = ${dns}${N}"
	done <<-_EOF
	$(get_dns 2>/dev/null)"
	_EOF

	mtu="$(ip link show dev "$INTERFACE" | sed -E -n "s/mtu\ ([0-9]+) ]]/\1/p")"
	[ -n "$MTU" ] && [ -n "$mtu" ] && new_config="${new_config}MTU = ${mtu}${N}"
	[ -n "$TABLE" ] && new_config="${new_config}Table = ${TABLE}${N}"
	[ $SAVE_CONFIG -eq 0 ] || new_config="${new_config}SaveConfig = true${N}"

	for cmd in $PRE_UP ; do
		new_config="${new_config}PreUp = ${cmd}${N}"
	done
	for cmd in $POST_UP ; do
		new_config="${new_config}PostUp = ${cmd}${N}"
	done
	for cmd in $PRE_DOWN ; do
		new_config="${new_config}PreDown = ${cmd}${N}"
	done
	for cmd in $POST_DOWN ; do
		new_config="${new_config}PostDown = ${cmd}${N}"
	done

	old_umask="$(umask)"
	umask 077
	trap 'rm -f "$CONFIG_FILE.tmp"; exit' INT TERM EXIT
	cmd wg showconf "$INTERFACE" | \
		awk -v ifs="$new_config" -v del="$N" \
			'{sub(/[(del)\r\n]+$/, "", ifs); sub(/\[Interface\]/, ifs); print;}' \
		>"$CONFIG_FILE.tmp" || die "Could not write configuration file"
	sync "$CONFIG_FILE.tmp"
	mv "$CONFIG_FILE.tmp" "$CONFIG_FILE" || die "Could not move configuration file"
	trap - INT TERM EXIT
	umask "$old_umask"
}

execute_hooks() {
	for hook in "$@"; do
		hook=$(echo "$hook" | sed -E "s/%i/$INTERFACE/g")
		echo "[#] $hook" >&2
		eval "$hook"
	done
}

cmd_usage() {
	cat >&2 <<-_EOF
	Usage: $PROGRAM [ up | down | save | strip ] [ CONFIG_FILE | INTERFACE ]

	  CONFIG_FILE is a configuration file, whose filename is the interface name
	  followed by \`.conf'. Otherwise, INTERFACE is an interface name, with
	  configuration found at /etc/wireguard/INTERFACE.conf. It is to be readable
	  by wg(8)'s \`setconf' sub-command, with the exception of the following additions
	  to the [Interface] section, which are handled by $PROGRAM:

	  - Address: may be specified one or more times and contains one or more
	    IP addresses (with an optional CIDR mask) to be set for the interface.
	  - DNS: an optional DNS server to use while the device is up.
	  - MTU: an optional MTU for the interface; if unspecified, auto-calculated.
	  - Table: an optional routing table to which routes will be added; if
	    unspecified or \`auto', the default table is used. If \`off', no routes
	    are added.
	  - PreUp, PostUp, PreDown, PostDown: script snippets which will be executed
	    by bash(1) at the corresponding phases of the link, most commonly used
	    to configure DNS. The string \`%i' is expanded to INTERFACE.
	  - SaveConfig: if set to \`true', the configuration is saved from the current
	    state of the interface upon shutdown.

	See wg-quick(8) for more info and examples.
	_EOF
}

cmd_up() {
	[ -z "$(ip link show dev "$INTERFACE" 2>/dev/null)" ] || die "\`$INTERFACE' already exists"
	trap 'del_if; exit' INT TERM EXIT
	execute_hooks "$PRE_UP"
	add_if
	set_config
	for addr in $ADDRESSES ; do
		add_addr "$addr"
	done
	set_mtu_up
	set_dns
	while read -r line ; do
		echo "$line" | sed -E -n "s/^.*\s+([0-9a-z:\.]*\/[0-9]*)/\1/p"
	done <<-_EOF | sort -nr -k 2 -t / | while read -r ip; do add_route "$ip"; done
	$(wg show "$INTERFACE" allowed-ips)
	_EOF
	execute_hooks "$POST_UP"
	trap - INT TERM EXIT
}

cmd_down() {
	wg show interfaces | grep "$INTERFACE" || die "\`$INTERFACE' is not a WireGuard interface"
	execute_hooks "$PRE_DOWN"
	[ $SAVE_CONFIG -eq 0 ] || save_config
	del_if
	unset_dns || true
	remove_firewall || true
	execute_hooks "$POST_DOWN"
}

cmd_save() {
	wg show interfaces | grep "$INTERFACE" || die "\`$INTERFACE' is not a WireGuard interface"
	save_config
}

cmd_strip() {
	echo "$WG_CONFIG"
}

# ~~ function override insertion point ~~

if [ "$#" -eq 1 ] && [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "help" ]; then
	cmd_usage
elif [ "$#" -eq 2 ] && [ "$1" = "up" ]; then
	auto_su
	parse_options "$2"
	cmd_up
elif [ "$#" -eq 2 ] && [ "$1" = "down" ]; then
	auto_su
	parse_options "$2"
	cmd_down
elif [ "$#" -eq 2 ] && [ "$1" = "save" ]; then
	auto_su
	parse_options "$2"
	cmd_save
elif [ "$#" -eq 2 ] && [ "$1" = "strip" ]; then
	auto_su
	parse_options "$2"
	cmd_strip
else
	cmd_usage
	exit 1
fi

exit 0
