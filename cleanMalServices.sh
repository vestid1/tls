#!/bin/sh

BASENAME=$0
DEBUG=1
GLOBAL_PATH=""

SYSTEMD_DIR="/etc/systemd/system"
MULTI_USER_DIR="$SYSTEMD_DIR/multi-user.target.wants"
INITD_DIR="/etc/init.d"
RCD_DIR="/etc/rc.d"
RC_INIT_DIR="$RCD_DIR/init.d"

cmd_e() {
	command -v "$1" > /dev/null 2>&1
}

cleanup(){
	cd / || exit 1

	selfPath=""
	if cmd_e realpath;then
		selfPath=$(realpath -eq "$BASENAME")
	elif cmd_e readlink;then
		selfPath=$(readlink -eq "$BASENAME")
	else
		selfPath="$BASENAME"
	fi

	if [ -n "$selfPath" ] && [ -f "$selfPath" ];then
		rm -rf "$selfPath"
	fi
}

trim(){
	stringVal=$1

	if cmd_e xargs;then
		stringVal=$(echo "$stringVal" | xargs)
	else
		stringVal=$(echo "$stringVal" | sed -r "s/^[[:space:]]+|[[:space:]]+$//g")
	fi

	printf "%s" "$stringVal"
}

killProcess(){
	_pname="$1"

	if pgrep -f "$_pname" > /dev/null 2>&1;then
		if [ "$DEBUG" -eq 1 ];then
			echo "[*] Killing process: $_pname"
		fi

		for p in $(pgrep -f "$_pname")
		do
			if [ -n "$p" ];then
				pstree -p "$p"|head -n 1|grep -oP '\(\K\d+(?=\))'|sort -r|xargs kill -9
			fi
		done
	fi
}

removeService(){
	serviceName="$1"
	sn1="${serviceName}.service"
	sp1="$SYSTEMD_DIR/$sn1"
	sp2="$MULTI_USER_DIR/$sn1"

	sp3="$INITD_DIR/$serviceName"
	sp4="$RCD_DIR/$serviceName"
	sp5="$RC_INIT_DIR/$serviceName"

	if [ -f "$sp1" ] || [ -f "$sp2" ];then
		if [ "$DEBUG" -eq 1 ];then
			echo "[*] Removing service: $serviceName"
		fi

		if cmd_e systemctl;then
			if systemctl status "$sn1";then
				systemctl stop "$sn1"
				systemctl disable "$sn1"
			fi
		fi

		if [ -f "$sp1" ];then
			rm -rf "$sp1"
		fi

		if [ -f "$sp2" ];then
			rm -rf "$sp2"
		fi
	fi

	if [ -f "$sp3" ];then
		$sp3 stop
		if cmd_e chatr;then
			chattr -ia "$sp3"
		fi
		rm -rf "$sp3"
	fi

	if [ -f "$sp4" ];then
		$sp4 stop
		if cmd_e chatr;then
			chattr -ia "$sp4"
		fi
		rm -rf "$sp4"
	fi

	if [ -f "$sp5" ];then
		$sp5 stop
		if cmd_e chatr;then
			chattr -ia "$sp5"
		fi
		rm -rf "$sp5"
	fi
}

setDefaultPath() {
	if [ "$DEBUG" -eq 1 ];then
		echo "[*] Setting default path"
	fi

	if [ -d "/usr/local/sbin" ];then
		if ! echo "$PATH"|grep -qoE '^/usr/local/sbin|:/usr/local/sbin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/local/sbin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/local/sbin"
			fi
		fi
	fi

	if [ -d "/usr/local/bin" ];then
		if ! echo "$PATH"|grep -qoE '^/usr/local/bin|:/usr/local/bin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/local/bin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/local/bin"
			fi
		fi
	fi

	if [ -d "/usr/sbin" ];then
		if ! echo "$PATH"|grep -qoE '^/usr/sbin|:/usr/sbin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/sbin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/sbin"
			fi
		fi
	fi

	if [ -d "/usr/bin" ];then
		if ! echo "$PATH"|grep -qoE '^/usr/bin|:/usr/bin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/usr/bin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/usr/bin"
			fi
		fi
	fi

	if [ -d "/sbin" ];then
		if ! echo "$PATH"|grep -qoE '^/sbin|:/sbin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/sbin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/sbin"
			fi
		fi
	fi

	if [ -d "/bin" ];then
		if ! echo "$PATH"|grep -qoE '^/bin|:/bin';then
			if [ -z "$GLOBAL_PATH" ];then
				GLOBAL_PATH="/bin"
			else
				GLOBAL_PATH="${GLOBAL_PATH}:/bin"
			fi
		fi
	fi

	if [ -n "$GLOBAL_PATH" ];then
		export PATH="$GLOBAL_PATH:$PATH"
	fi

	if command -v rm 2>/dev/null|grep -qE 'alias';then
		unalias rm
	fi
}

cleanMaliciousCrond(){
	if [ -d /etc/cron.d ];then
		find /etc/cron.d/ -type f -user root -group lscpd|while read -r cronFile; do
			if ! echo "$cronFile"|grep -qiE 'patch';then
				if [ "$DEBUG" -eq 1 ];then
					echo "[*] Cleaning malicious crond $cronFile"
				fi

				if cmd_e chattr;then
					chattr -ia "$cronFile"
				fi
				rm -f "$cronFile"
			fi
		done
	fi

	if [ -d /var/spool/cron ];then
		find /var/spool/cron/ -type f -user root -group lscpd|while read -r cronFile; do
			if [ "$DEBUG" -eq 1 ];then
				echo "[*] Cleaning malicious crond $cronFile"
			fi

			if cmd_e chattr;then
				chattr -ia "$cronFile"
			fi
			rm -f "$cronFile"
		done
	fi
}

cleanMaliciousServices(){
	if [ "$DEBUG" -eq 1 ];then
		echo "[*] Cleaning malicious services"
	fi
	removeService "sshdrs"

	_f1="/var/zzc64"
	if [ -f "$_f1" ];then
		if cmd_e chattr;then
			chattr -ia "$_f1"
		fi
		rm -rf "$_f1"
	fi

	killProcess "/var/zzc64"
}

cleanMinerServices(){
	find /etc/systemd/system/ -type f -name '*miner*'|while read -r sname
	do
		_baseName=$(basename "$sname")
		_cleanName=$(echo "$_baseName"|sed -r 's/\.service//g')

		if [ "$DEBUG" -eq 1 ];then
			echo "[*] Cleaning miner service $_cleanName"
		fi

		removeService "$_cleanName"
	done

	_f1="/tmp/4thepool"
	if [ -d "$_f1" ];then
		if cmd_e chattr;then
			chattr -R -ia "$_f1"
		fi
		rm -rf "$_f1"
	fi

	killProcess "/tmp/4thepool/xmrig"
}

cleanMaliciousLibrary(){
	preload_file="/etc/ld.so.preload"
	infected_dir="/etc/data"
	infected_lib="libsystem.so"

	if [ -f "$preload_file" ];then
		if grep -qE "${infected_dir}/${infected_lib}" "$preload_file";then
			if [ "$DEBUG" -eq 1 ];then
				echo "[*] Cleaning malicious library ${infected_dir}/${infected_lib}"
			fi

			if cmd_e chattr;then
				if [ -d "$infected_dir" ];then
					chattr -R -ia "$infected_dir"
				fi
				chattr -ia "$preload_file"
			fi
			sed -i "/$infected_lib/d" "$preload_file"
			rm -rf "$infected_dir"
		fi
	fi
}

cleanMaliciousActivities(){
	# if [ "$DEBUG" -eq 1 ];then
	# 	echo "[*] Cleaning malicious activities"
	# fi
	killProcess "/nvm\.(x(86|64)(_64)?)"
	killProcess "ppz([0-9]+)\.py"

	killProcess "\.network-setup"
	if [ -d /usr/.network-setup ];then
		if cmd_e chattr;then
			chattr -R -ia /usr/.network-setup
		fi
		rm -rf /usr/.network-setup
	fi

	killProcess "\.x/static"
	killProcess "tmux|\./static"

	if [ -f /root/x.xz ];then
		if cmd_e chattr;then
			chattr -ia /root/x.xz
		fi
		rm -f /root/x.xz
	fi

	if [ -d /root/.x ];then
		if cmd_e chattr;then
			chattr -R -ia /root/.x
		fi
		rm -rf /root/.x
	fi
}

cleanMaliciousCrontab(){
	if crontab -l|grep -qiE 'secure\/atdb|supeople\.ru';then
		if [ "$DEBUG" -eq 1 ];then
			echo "[*] Cleaning malicious crontab"
		fi

		if cmd_e chattr;then
			if [ -f /var/spool/cron/root ];then
				chattr -ia /var/spool/cron/root
				rm -f /var/spool/cron/root
			fi
			if [ -f /var/spool/cron/crontabs/root ];then
				chattr -ia /var/spool/cron/crontabs/root
			fi
		fi
		crontab -l|sed -r '/secure\/atdb|supeople\.ru/d'|crontab -
	fi
}

cleanMaliciousDocker(){
	if cmd_e docker;then
		docker ps -a|grep traffmonetizer|awk '{print $1}'|while read -r _cid
		do
			if [ -n "$_cid" ];then
				if [ "$DEBUG" -eq 1 ];then
					echo "[*] Cleaning malicious docker container $_cid"
				fi

				docker stop "$_cid"
				docker rm "$_cid"
				docker image prune -af
				docker volume prune -f
				docker network prune -f
			fi
		done
	fi
}

setDefaultPath

cleanMaliciousCrond
cleanMaliciousServices
cleanMinerServices

cleanMaliciousLibrary
cleanMaliciousActivities
cleanMaliciousCrontab
cleanMaliciousDocker

cleanup

exit 0
