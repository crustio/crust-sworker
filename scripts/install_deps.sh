#!/bin/bash
function installPrerequisites()
{
    # For SGX PSW
    checkAndInstall "${sgxpswprereq[*]}"

    # For SGX SDK
    checkAndInstall "${sgxsdkprereq[*]}"

    # For others
    checkAndInstall "${othersprereq[*]}"
}

function installSGXSDK()
{
    if hasInstalledSGXSDK; then
        return 0
    fi
    local cmd=""
    local expCmd=""
    local ret=0

    # Unstall previous SGX component
    uninstallSGX

    cd $rsrcdir
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
            ret=$?
        fi
        checkRes $ret "quit" "success"
    done
    cd - &>/dev/null
}

function installSGXSSL()
{
    verbose INFO "Checking sgxssl..." h
    if [ -d "$sgxssldir" ]; then
        verbose INFO "yes" t
        return
    fi
    verbose ERROR "no" t

    local ret_l=0

    # Install SGXSDK
    > $SYNCFILE
    setTimeWait "$(verbose INFO "Installing SGX SSL(about 60s)..." h)" $SYNCFILE &
    cd $rsrcdir
    sgxssltmpdir=$rsrcdir/$(unzip -l $sgxsslpkg | awk '{print $NF}' | awk -F/ '{print $1}' | grep intel | head -n 1)
    sgxssl_openssl_source_dir=$sgxssltmpdir/openssl_source
    unzip $sgxsslpkg &>$ERRFILE
    if [ $? -ne 0 ]; then
        verbose "failed" t
        exit 1
    fi
    cd - &>/dev/null

    # build SGX SSL
    cd $sgxssltmpdir/Linux
    cp $opensslpkg $sgxssl_openssl_source_dir
    toKillPID[${#toKillPID[*]}]=$!
    make all test &>$ERRFILE && make install &>$ERRFILE
    checkRes $? "quit" "success" "$SYNCFILE"
    cd - &>/dev/null

    if [ x"$sgxssltmpdir" != x"/" ]; then
        rm -rf $sgxssltmpdir
    fi
}

function hasInstalledSGXSDK()
{
    local installed=true
    for dep in ${!checkArry[@]}; do
        verbose INFO "Checking $dep..." h
        if ! dpkg -l | grep $dep &>/dev/null && [ ! -e "$inteldir/$dep" ]; then
            verbose ERROR "no" t
            installed=false
        else
            verbose INFO "yes" t
            checkArry[$dep]=1
        fi
    done

    $installed && { source $sgx_env_file; return 0; }

    return 1
}

function uninstallSGX()
{
    for el in ${delOrder[@]}; do
        if [ ${checkArry[$el]} -eq 1 ]; then
            verbose INFO "Uninstalling previous SGX $el..." h
            if echo $el | grep lib &>/dev/null; then
                dpkg -r "${el}-dev" &>$ERRFILE
                dpkg -r "${el}" &>$ERRFILE
                checkRes $? "quit" "success"
            else
                $inteldir/$el/uninstall.sh &>$ERRFILE
                checkRes $? "quit" "success"
            fi
        fi
    done

    rm -rf $sgxssldir
}

function checkAndInstall()
{
    for dep in $1; do
        verbose INFO "Checking $dep..." h
        dpkg -l | grep $dep &>/dev/null
        checkRes $? "return" "yes"
        if [ $? -ne 0 ]; then
            > $SYNCFILE
            setTimeWait "$(verbose INFO "Installing $dep..." h)" $SYNCFILE &
            toKillPID[${#toKillPID[*]}]=$!
            apt-get install -y $dep &>$ERRFILE
            checkRes $? "quit" "success" "$SYNCFILE"
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
    expect "to install in :" { send "$inteldir\n" }
    expect eof
EOF
    cat $TMPFILE | grep successful &>/dev/null
    return $?
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
    if [ x"$sgxssltmpdir" != x"" ] && [ x"$sgxssltmpdir" != x"/" ]; then
        rm -rf $sgxssltmpdir
    fi

    #kill -- -$selfPID
}

############## MAIN BODY ###############
# basic variable
basedir=$(cd `dirname $0`;pwd)
TMPFILE=$basedir/tmp.$$
ERRFILE=$basedir/err.log
rsrcdir=$basedir/../resource
crustteedir=/opt/crust/crust-tee
inteldir=/opt/intel
sgxssldir=$inteldir/sgxssl
sgxssltmpdir=""
selfPID=$$
OSID=$(cat /etc/os-release | grep '^ID\b' | grep -Po "(?<==).*")
OSVERSION=$(cat /etc/os-release | grep 'VERSION_ID' | grep -Po "(?<==\").*(?=\")")
tmo=180
SYNCFILE=$basedir/.syncfile
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
# SGX prerequisites
sgxsdkprereq=(build-essential python)
sgxpswprereq=(libssl-dev libcurl4-openssl-dev libprotobuf-dev)
othersprereq=(libboost-all-dev libleveldb-dev openssl)
# SGX associate array
delOrder=(libsgx-enclave-common-dev libsgx-enclave-common sgxdriver sgxsdk)
declare -A checkArry="("$(for el in ${delOrder[@]}; do echo [$el]=0; done)")"
# Crust related
crust_env_file=$crustteedir/etc/environment
sgx_env_file=/opt/intel/sgxsdk/environment


. $basedir/utils.sh

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
        verbose ERROR "Install expect failed!"
        exit 1
    fi
fi

# Installing Prerequisites
installPrerequisites

# Installing SGX SDK
installSGXSDK

# Installing SGX SSL
installSGXSSL
