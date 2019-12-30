#!/bin/bash
function getPackage()
{
    timeout $tmo wget -P $tempdir $1
    if [ $? -ne 0 ]; then
        verbose ERROR "Get package $1 failed!Please try again!" t
        exit 1
    fi
    {
        flock -x 222 -w $tmo
        ((gotPkgNum++))
    } 222<> lockfile
}

function startAPP()
{
    cd $appdir
    make clean &>/dev/null
    setTimeWait "$(verbose INFO "Making application..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make &>/dev/null
    checkRes $? "quit" "$SYNCFILE"
    nohup ./app $startType &>$APPLOG &
    if [ $? -ne 0 ]; then
        verbose ERROR "Start app failed!"
    fi
    cd - &>/dev/null
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
        verbose INFO "SGX SSL has been installed!"
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

function installOPENSSL()
{
    if [ -e "/opt/openssl/1.1.1d" ]; then
        verbose WARN "openssl-1.1.1d has been installed! Please check!"
        return
    fi
    tar -xvf $opensslpkg -C $rsrcdir
    cd $openssldir
    verbose INFO "Configure openssl..." h
    ./config --prefix=/opt/openssl/1.1.1d --openssldir=/opt/openssl/1.1.1d
    checkRes $?
    verbose INFO "Installing openssl..." h
    make && sudo make install
    checkRes $?
    cd - &>/dev/null
}

function installIPFS()
{
    if [ -d "$IPFSDIR" ]; then
        verbose INFO "IPFS has been initialized." n
    else
        local res=0
        verbose INFO "Init ipfs..." h
        $IPFS init &>/dev/null
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

    verbose INFO "Starting up IPFS..." h
    local ipfspid=$(ps -ef | grep ipfs | grep -v grep | awk '{print $2}')
    if [ x"$ipfspid" != x"" ]; then
        kill -9 $ipfspid
        if [ $? -ne 0 ]; then
            # If failed by using current user, kill it using root
            execWithExpect "kill -9 $ipfspid"
        fi
    fi
    nohup $IPFS daemon &>$NOHUPOUT &
    checkRes $? "quit"

    verbose INFO "Install IPFS successfully!"
}

function uninstallSGXSDK()
{
    for el in ${delOrder[@]}; do
        [ x"$el" = x"sgxssl" ] && continue
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
    if grep "SGX_SDK" ~/.bashrc &>/dev/null; then
        verbose WARN "SGX environment has been set in ~/.bashrc!
            Please check if it is the right one!"
        return
    fi
cat << EOF >> ~/.bashrc
# SGX configuration
export SGX_SDK=/opt/intel/sgxsdk
export SGX_SSL=/opt/intel/sgxssl
export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs:$SGX_SSL/lib64
EOF

    verbose WARN "Please run 'source ~/.bashrc' command!!!"
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
appdir=$basedir/../Miner
instdir=$basedir/..
TMPFILE=$appdir/tmp.$$
rsrcdir=$appdir/resource
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
# Control configuration
instTimeout=30
toKillPID=()
startType=$1
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
# IPFS related
IPFSDIR=$HOME"/.ipfs/"
IPFS=$instdir/bin/ipfs
SWARMKEY=$instdir/etc/swarm.key
IPFS_SWARM_ADDR_IPV4=\"/ip4/0.0.0.0/tcp/4001\"
IPFS_SWARM_ADDR_IPV6=\"/ip6/::/tcp/4001\"
NOHUPOUT=$instdir/nohup.out
# App related
APPLOG=$appdir/logs/entry.log

trap "success_exit" INT
trap "success_exit" EXIT

# Download packages
#verbose INFO "Downloading SGX SDK packages..." h
#for package in ${packages[@]}; do
#    getPackage $package &
#done
## Wait for downloading...
#while [ $gotPkgNum < ${#packages[*]} ]; do
#    sleep 1
#done
#verbose INFO "success" t

if [ x"$startType" != x"server" ]; then
    startType=""
fi

read -p "Please input your account password: " passwd
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

verbose INFO "---------- Installing SGX SDK ----------" n
if checkSGXSDK; then
    ### Install sgx
    installSGXSDK
    
    ### Install openssl 
    #installOPENSSL
else
    verbose INFO "SGX SDK Dependencies have been installed!!!"
fi
    
# Install SGX SSL
echo
verbose INFO "---------- Installing SGX SSL ----------" n
installSGXSSL

# Install IPFS
echo
verbose INFO "---------- Installing IPFS ----------" n
installIPFS

# Set environment
echo
verbose INFO "---------- Setting environment ----------" n
setEnv

# Start crust tee
echo
verbose INFO "---------- Start Application ----------" n
startAPP
