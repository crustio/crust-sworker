#!/bin/bash
function installAPP()
{
    # Install tee-app dependencies
    verbose INFO "Installing app dependencies..." h
    checkRes $? "quit"

    local res=0
    cd $appdir
    make clean &>/dev/null
    setTimeWait "$(verbose INFO "Buiding application..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make &>/dev/null
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
    true > $crustteedir/.ipc

    # Set environment
    setEnv

    verbose INFO "Install application successfully!"
}

function installSGXSDK()
{
    local cmd=""
    local expCmd=""
    echo
    verbose INFO "Uninstalling previous SGX SDK..."
    uninstallSGXSDK

    cd $rsrcdir
    echo
    for dep in ${sdkInstOrd[@]}; do 
        verbose INFO "Installing $dep..." h
        cmd=""
        echo $dep | grep lib &>/dev/null && cmd="dpkg -i"
        expCmd="execWithExpect"
        [[ $dep =~ sdk ]] && expCmd="execWithExpect_sdk"
        $expCmd "$cmd" $rsrcdir/$dep
        checkRes $? "quit"
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
    #verbose INFO "Making SGX SSL..." h
    cp $opensslpkg $sgxssl_openssl_source_dir
    touch $SYNCFILE
    setTimeWait "$(verbose INFO "Making SGX SSL..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make all test &>/dev/null
    checkRes $? "quit" "$SYNCFILE"
    echo
    verbose INFO "Installing SGX SSL..." h
    execWithExpect "make install"
    checkRes $? "quit"
    cd - &>/dev/null

    if [ x"$sgxssldir" != x"/" ]; then
        rm -rf $sgxssldir
    fi

    verbose INFO "Install SGX SSL successfully!!!"
}

function installIPFS()
{
    if [ -d "$IPFSDIR" ]; then
        verbose INFO "IPFS has been initialized." n
    else
        local res=0
        local ipfspid=$(ps -ef | grep ipfs | grep -v grep | awk '{print $2}')
        if [ x"$ipfspid" != x"" ]; then
            kill -9 $ipfspid
            if [ $? -ne 0 ]; then
                # If failed by using current user, kill it using root
                execWithExpect "kill -9 $ipfspid"
            fi
        fi
        verbose INFO "Init ipfs..." h
        $IPFS init
        checkRes $? "return"
    
        verbose INFO "Set swarm key ..." h
        mkdir -p $IPFSDIR
        cp $SWARMKEY "$IPFSDIR"
        checkRes $? "return"
    
        verbose INFO "Remove public bootstrap..." h
        $IPFS bootstrap rm --all &>/dev/null
        checkRes $? "return"
    
        if [ -z "$MASTER_ADDRESS" ]; then
            verbose INFO "This node is master node" n
        else
            verbose INFO "This node is slave, master node is '[$MASTER_ADDRESS]'' ..." n
            $IPFS bootstrap add $MASTER_ADDRESS &>/dev/null
            checkRes $? "return"
        fi
    
        verbose INFO "Set system fire wall..." h
        execWithExpect "ufw allow 22"
        res=$(($?|$res))
        execWithExpect "ufw allow 5001"
        res=$(($?|$res))
        execWithExpect "ufw allow 4001"
        res=$(($?|$res))
        execWithExpect "ufw enable"
        res=$(($?|$res))
        execWithExpect "ufw reload"
        res=$(($?|$res))
        checkRes $res "return"
    
        verbose INFO "Set swarm address ..." h
        $IPFS config Addresses.Swarm --json "[$IPFS_SWARM_ADDR_IPV4, $IPFS_SWARM_ADDR_IPV6]" &>/dev/null
        checkRes $? "return"
    
        verbose INFO "Set api address ..." h
        $IPFS config Addresses.API /ip4/0.0.0.0/tcp/5001 &>/dev/null
        checkRes $? "return"
    
        verbose INFO "Remove all data ..." h
        $IPFS pin rm $($IPFS pin ls -q --type recursive) &>/dev/null
        $IPFS repo gc &>/dev/null
        checkRes $? "return"
    fi
}

function uninstallOldCrust()
{
    verbose INFO "Removing old crust..." h
    local ret=0
    if [ ! -e "$crustteedir" ]; then
        verbose INFO "SUCCESS" t
        return
    fi
    cd $crustteedir
    if [ -e "scripts/uninstall.sh" ]; then
        ./scripts/uninstall.sh &>/dev/null
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
                execWithExpect "dpkg -r" ${el}-dev
                execWithExpect "dpkg -r" ${el}
                checkRes $?
            else
                execWithExpect "" $inteldir/$el/uninstall.sh
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
    spawn sudo $cmd $pkgPath
    expect "password"        { send "$passwd\n"  }
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
        case $err_op in 
            quit)       exit 1;;
            return)     return 1;;
            *)          ;;
        esac
        return 1
    fi

    eval "verbose INFO "SUCCESS" t >$descriptor"

    while [ -s $descriptor ]; do
        sleep 1
    done
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
        ERROR)  color=$RED ;;
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
uid=$(id -u)
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
#delOrder=(libsgx-enclave-common sgxdriver sgxsdk sgxssl)
delOrder=(libsgx-enclave-common sgxdriver sgxsdk)
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


verbose WARN "Make sure $USER can run 'sudo'!"

read -p "Please input your password: " -s passwd
echo

# check if there is expect installed
which expect &>/dev/null
if [ $? -ne 0 ]; then
    sudo apt-get install expect
    if [ $? -ne 0 ]; then
        verbose ERROR "Please install expect with root!"
        exit 1
    fi
fi

echo
verbose INFO "---------- Uninstalling previous crust-tee ----------" n
uninstallOldCrust

# Create directory
verbose INFO "Creating and setting diretory related..." h
res=0
execWithExpect "mkdir -p $crustteedir"
res=$(($?|$res))
execWithExpect "chown -R $uid:$uid $crustteedir"
res=$(($?|$res))
execWithExpect "mkdir -p $inteldir"
res=$(($?|$res))
checkRes $res "quit"

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

# Install IPFS
echo
verbose INFO "---------- Installing IPFS ----------" n
installIPFS
echo

verbose INFO "Crust-tee has been installed in /opt/crust! Go to /opt/crust/crust-tee and run scripts/start.sh to start crust.\n"
