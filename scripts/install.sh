#!/bin/bash
function installAPP()
{
    # Install tee-app dependencies
    local res=0
    cd $appdir
    make clean &>/dev/null
    setTimeWait "$(verbose INFO "Buiding application(about 50s)..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make &>$ERRFILE
    checkRes $? "quit" "$SYNCFILE"
    cp $appname ../bin
    if [ ! -e "../etc/$enclaveso" ]; then
        cp $enclaveso ../etc
    fi
    cp $configfile ../etc
    cd - &>/dev/null
    
    # Copy related files to install directory
    cp -r $instdir/bin $crustteedir
    cp -r $instdir/etc $crustteedir
    cp -r $instdir/scripts $crustteedir
    cp -r $instdir/VERSION $crustteedir
    mkdir -p $crustteedir/log

    # Set environment
    setEnv

    verbose INFO "Install application successfully!"
}

function installPrerequisites()
{
    # For SGX PSW
    verbose INFO "Installing SGX PSW prerequisites..." h
    apt-get install -y libssl-dev libcurl4-openssl-dev libprotobuf-dev &>/dev/null
    checkRes $? "quit"

    # For SGX SDK
    verbose INFO "Installing SGX SDK prerequisites..." h
    apt-get install -y build-essential python &>/dev/null
    checkRes $? "quit"

    # For others
    verbose INFO "Installing other prerequisites..." h
    apt-get install -y libboost-all-dev openssl &>/dev/null
    checkRes $? "quit"

    verbose INFO "Install prerequisites successfully!"
}

function installSGXSDK()
{
    local cmd=""
    local expCmd=""
    local ret=0
    echo
    verbose INFO "Uninstalling previous SGX SDK..."
    uninstallSGXSDK

    cd $rsrcdir
    echo
    verbose INFO "Installing SGX SDK..."
    for dep in ${sdkInstOrd[@]}; do 
        verbose INFO "Installing $dep..." h
        if echo $dep | grep lib &>/dev/null; then
            dpkg -i $rsrcdir/$dep &>$ERRFILE
            ret=$?
        elif [[ $dep =~ sdk ]]; then
            execWithExpect_sdk "" "$rsrcdir/$dep"
            ret=$?
        else
            $rsrcdir/$dep &>$ERRFILE
        fi
        checkRes $ret "quit"
    done
    cd - &>/dev/null
    verbose INFO "Install SGX SDK successfully!!!"
}

function installSGXSSL()
{
    if [ -d "$inteldir/sgxssl" ]; then
        verbose INFO "SGX SSL has been installed." n
        return
    fi
    # get sgx ssl package
    #verbose INFO "Downloading intel SGX SSL..." h
    #timeout $tmo wget -P $tempdir -O $SGXSSLPKGNAME $SGXSSLURL
    #checkRes $? "SGX SSL"
    cd $rsrcdir
    sgxssldir=$rsrcdir/$(unzip -l $sgxsslpkg | awk '{print $NF}' | awk -F/ '{print $1}' | grep intel | head -n 1)
    sgxssl_openssl_source_dir=$sgxssldir/openssl_source
    verbose INFO "Unzip SGX SSL package..." h
    unzip $sgxsslpkg &>/dev/null
    checkRes $? "return"
    cd - &>/dev/null

    # get openssl package
    #verbose INFO "Downloading openssl package..." h
    #timeout $tmo wget -P $sgxssl_openssl_source_dir -O $opensslpkg $OPENSSLURL
    #checkRes $? "openssl"

    # build SGX SSL
    cd $sgxssldir/Linux
    cp $opensslpkg $sgxssl_openssl_source_dir
    touch $SYNCFILE
    setTimeWait "$(verbose INFO "Making SGX SSL(about 60s)..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make all test &>$ERRFILE
    checkRes $? "quit" "$SYNCFILE"
    echo
    verbose INFO "Installing SGX SSL..." h
    make install &>$ERRFILE
    checkRes $? "quit"
    cd - &>/dev/null

    if [ x"$sgxssldir" != x"/" ]; then
        rm -rf $sgxssldir
    fi

    verbose INFO "Install SGX SSL successfully!!!"
}

function uninstallOldCrustTee()
{
    verbose INFO "Removing old crust tee..." h
    local ret=0
    if [ ! -e "$crustteedir" ]; then
        verbose INFO "SUCCESS" t
        return
    fi
    cd $crustteedir
    if [ -e "scripts/uninstall.sh" ]; then
        ./scripts/uninstall.sh &>$ERRFILE
        ret=$?
    else
        rm -rf *
        ret=$?
    fi
    cd - &>/dev/null
    checkRes $ret "quit"
}

function uninstallSGXSDK()
{
    for el in ${delOrder[@]}; do
        if [ ${checkArry[$el]} -eq 1 ]; then
            verbose INFO "Uninstalling previous SGX $el..." h
            if echo $el | grep lib &>/dev/null; then
                dpkg -r "${el}-dev" &>/dev/null
                dpkg -r "${el}" &>/dev/null
                checkRes $?
            else
                $inteldir/$el/uninstall.sh &>/dev/null
                checkRes $?
            fi
        fi
    done
}

function execWithExpect()
{
    local cmd=$1
    local pkgPath=$2
expect << EOF > $TMPFILE
    set timeout $instTimeout
    spawn sudo $cmd $pkgPath
    expect "password"        { send "$passwd\n"  }
    expect eof
EOF
    ! cat $TMPFILE | grep "error\|ERROR" &>/dev/null
    return $?
}

function execWithExpect_sdk()
{
    local cmd=$1
    local pkgPath=$2
expect << EOF > $TMPFILE
    set timeout $instTimeout
    spawn $cmd $pkgPath
    expect "yes/no"          { send "no\n"  }
    expect "to install in :" { send "/opt/intel\n" }
    expect eof
EOF
    cat $TMPFILE | grep successful &>/dev/null
    return $?
}

function checkSGXSDK()
{
    verbose INFO "Checking SGX environment..." n
    for dep in ${!checkArry[@]}; do
        verbose INFO "Checking $dep..." h
        if ! dpkg -l | grep $dep &>/dev/null && [ ! -e "$inteldir/$dep" ]; then
            verbose ERROR "FAILED" t
            installEnv=true
        else
            verbose INFO "SUCCESS" t
            checkArry[$dep]=1
        fi
    done

    $installEnv && return 0
    return 1
}

function setEnv()
{

cat << EOF > $crust_env_file
# SGX configuration
export SGX_SDK=/opt/intel/sgxsdk
export SGX_SSL=/opt/intel/sgxssl
export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs:$SGX_SSL/lib64
EOF

}

function checkRes()
{
    local res=$1
    local err_op=$2
    local descriptor=$3

    if [ x"$descriptor" = x"" ] ; then 
        descriptor="&1"
    fi

    if [ $res -ne 0 ]; then
        eval "verbose ERROR "FAILED" t >$descriptor"
    else
        eval "verbose INFO "SUCCESS" t >$descriptor"
    fi

    while [ -s "$descriptor" ]; do
        sleep 1
    done

    if [ $res -ne 0 ]; then
        case $err_op in
            quit)       
                verbose ERROR "Unexpected error occurs!Please check $ERRFILE for details!"
                exit 1
                ;;
            return)     
                return 1
                ;;
            *)  ;;
        esac
    fi
}

function setTimeWait()
{
    local info=$1
    local syncfile=$2
    local index=1
    local timeout=100
    while [ ! -s "$syncfile" ] && [ $timeout -gt 0 ]; do
        printf "%s\r" "${info}${index}s"
        ((index++))
        ((timeout--))
        sleep 1
    done

    echo "${info}$(cat $SYNCFILE)"
    true > $SYNCFILE
}

function verbose()
{
    local type=$1
    local info=$2
    local tips=$3
    local color=$GREEN
    local nc=$NC
    local opt="-e"
    local content=""
    local time=`date "+%Y/%m/%d %T.%3N"`

    case $type in
        ERROR)  color=$HRED ;;
        WARN)   color=$YELLOW ;;
        INFO)   color=$GREEN ;;
    esac
    case $tips in 
        h)      
            opt="-n"
            content="$time [$type] $info"
            ;;
        t)      
            opt="-e"
            content="${color}$info${nc}"
            ;;
        n)
            content="$time [$type] $info"
            ;;
        *)
            content="${color}$time [$type] $info${nc}"
    esac
    echo $opt $content
}

function success_exit()
{
    rm -f $TMPFILE

    rm -f $SYNCFILE &>/dev/null

    # Kill alive useless sub process
    for el in ${toKillPID[@]}; do
        if ps -ef | grep -v grep | grep $el &>/dev/null; then
            kill -9 $el
        fi
    done

    # delete sgx ssl temp directory
    if [ x"$sgxssldir" != x"" ] && [ x"$sgxssldir" != x"/" ]; then
        rm -rf $sgxssldir
    fi

    #kill -- -$selfPID
}

############## MAIN BODY ###############
# color
RED='\033[0;31m'
HRED='\033[1;31m'
GREEN='\033[0;32m'
HGREEN='\033[1;32m'
YELLOW='\033[0;33m'
HYELLOW='\033[1;33m'
NC='\033[0m'
# basic variable
basedir=$(cd `dirname $0`;pwd)
appdir=$basedir/Miner
instdir=$basedir
TMPFILE=$appdir/tmp.$$
ERRFILE=$basedir/err.log
rsrcdir=$instdir/resource
crustteedir=/opt/crust/crust-tee
inteldir=/opt/intel
installEnv=false
sgxssldir=""
sgxssl_openssl_source_dir=""
selfPID=$$
gotPkgNum=0
lockfile=$appdir/lockfile
OSID=$(cat /etc/os-release | grep '^ID\b' | grep -Po "(?<==).*")
OSVERSION=$(cat /etc/os-release | grep 'VERSION_ID' | grep -Po "(?<==\").*(?=\")")
tmo=180
SYNCFILE=$instdir/.syncfile
res=0
uid=$(stat -c '%U' $basedir)
# Control configuration
instTimeout=30
toKillPID=()
# SGX SDK
SDKURL="https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/${OSID}${OSVERSION}-server/sgx_linux_x64_sdk_2.7.101.3.bin"
DRIVERURL="https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/${OSID}${OSVERSION}-server/sgx_linux_x64_driver_2.6.0_4f5bb63.bin"
PSWURL="https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/${OSID}${OSVERSION}-server/libsgx-enclave-common_2.7.101.3-xenial1_amd64.deb"
PSWDEVURL="https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/${OSID}${OSVERSION}-server/libsgx-enclave-common-dev_2.7.101.3-xenial1_amd64.deb"
# SGX SSL
SGXSSLURL="https://codeload.github.com/intel/intel-sgx-ssl/zip/master"
SGXSSLPKGNAME="intel-sgx-ssl-master.zip"
OPENSSLURL="https://www.openssl.org/source/openssl-1.1.1d.tar.gz"
# downloaded files
packages=($SDKURL $DRIVERURL $PSWURL $PSWDEVURL $SGXSSLURL $OPENSSLURL)
sdkpkg=$(basename $SDKURL)
driverpkg=$(basename $DRIVERURL)
pswpkg=$(basename $PSWURL)
pswdevpkg=$(basename $PSWDEVURL)
sgxsslpkg=$rsrcdir/$SGXSSLPKGNAME
opensslpkg=$rsrcdir/$(basename $OPENSSLURL)
openssldir=$rsrcdir/$(basename $OPENSSLURL | grep -Po ".*(?=\.tar)")
sdkInstOrd=($driverpkg $pswpkg $pswdevpkg $sdkpkg)
# SGX associate array
delOrder=(libsgx-enclave-common-dev libsgx-enclave-common sgxdriver sgxsdk)
declare -A checkArry="("$(for el in ${delOrder[@]}; do echo [$el]=0; done)")"
# App related
appname="crust-tee"
enclaveso="enclave.signed.so"
configfile="Config.json"
# IPFS related
IPFSDIR=$HOME/.ipfs
IPFS=$crustteedir/bin/ipfs
SWARMKEY=$crustteedir/etc/swarm.key
IPFS_SWARM_ADDR_IPV4=\"/ip4/0.0.0.0/tcp/4001\"
IPFS_SWARM_ADDR_IPV6=\"/ip6/::/tcp/4001\"
# Crust related
crust_env_file=$crustteedir/etc/environment

trap "success_exit" INT
trap "success_exit" EXIT

if [ $(id -u) -ne 0 ]; then
    verbose ERROR "Please run with sudo!"
    exit 1
fi

# check if there is expect installed
which expect &>/dev/null
if [ $? -ne 0 ]; then
    apt-get install expect
    if [ $? -ne 0 ]; then
        verbose ERROR "Please install expect with root!"
        exit 1
    fi
fi

echo
verbose INFO "---------- Uninstalling previous crust-tee ----------" n
uninstallOldCrustTee

# Create directory
verbose INFO "Creating and setting diretory related..." h
res=0
mkdir -p $crustteedir
res=$(($?|$res))
mkdir -p $inteldir
res=$(($?|$res))
checkRes $res "quit"

echo
verbose INFO "---------- Installing Prerequisites ----------" n
installPrerequisites

echo
verbose INFO "---------- Installing SGX SDK ----------" n
if checkSGXSDK; then
    ### Install sgx
    installSGXSDK
else
    verbose INFO "SGX SDK Dependencies have been installed!!!"
fi

# Install SGX SSL
echo
verbose INFO "---------- Installing SGX SSL ----------" n
installSGXSSL

# Install Application
echo
verbose INFO "---------- Installing Application ----------" n
installAPP

verbose INFO "Changing diretory owner..." h
chown -R $uid:$uid $crustteedir
checkRes $res "quit"


verbose INFO "Crust-tee has been installed in /opt/crust/crust-tee! Go to /opt/crust/crust-tee and follow README to start crust.\n"
