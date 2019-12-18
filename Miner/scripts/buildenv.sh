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

function installSGXSDK()
{
    local cmd=""
    local expCmd=""
    echo
    verbose INFO "Uninstalling previous SGX SDK..."
    uninstallSGXSDK

    cd $rsrcdir
    echo
    verbose INFO "Installing SGX SDK..."
    for dep in ${sdkInstOrd[@]}; do 
        verbose INFO "Installing $dep..." h
        cmd=""
        echo $dep | grep lib &>/dev/null && cmd="dpkg -i"
        expCmd="execWithExpect"
        [[ $dep =~ sdk ]] && expCmd="execWithExpect_sdk"
        $expCmd "$cmd" $rsrcdir/$dep
        checkRes $? true
    done
    cd - &>/dev/null
    verbose INFO "Install SGX SDK successfully!!!"
}

function installSGXSSL()
{
    # get sgx ssl package
    #verbose INFO "Downloading intel SGX SSL..." h
    #timeout $tmo wget -P $tempdir -O $SGXSSLPKGNAME $SGXSSLURL
    #checkRes $? "SGX SSL"
    cd $rsrcdir
    sgxssldir=$rsrcdir/$(unzip -l $sgxsslpkg | awk '{print $NF}' | awk -F/ '{print $1}' | grep intel | head -n 1)
    sgxssl_openssl_source_dir=$sgxssldir/openssl_source
    unzip $sgxsslpkg
    cd -

    # get openssl package
    #verbose INFO "Downloading openssl package..." h
    #timeout $tmo wget -P $sgxssl_openssl_source_dir -O $opensslpkg $OPENSSLURL
    #checkRes $? "openssl"

    # build SGX SSL
    cd $sgxssldir/Linux
    verbose INFO "Making SGX SSL..." h
    make all test
    checkRes $? true
    verbose INFO "Installing SGX SSL..." h
    sudo make install
    checkRes $? true
    cd - &>/dev/null

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
    verbose INFO "Checking SGX environment..."
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
    local quit=$2

    if [ $res -ne 0 ]; then
        verbose ERROR "FAILED" t
        if [ x"$quit" = x"true" ]; then
            exit 1
        fi
        return
    fi

    verbose INFO "SUCCESS" t
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
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs:$SGX_SSL/lib64:/opt/openssl/1.1.1d/lib
EOF

    verbose WARN "Please run 'source ~/.bashrc' command!!!"
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
        *)
            content="${color}$time [$type] $info${nc}"
    esac
    echo $opt $content
}

function success_exit()
{
    #rm -rf $tempdir
    rm -f $TMPFILE
    kill -- -$selfPID
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
rootdir=$basedir/..
#tempdir=$(mktemp -d)
TMPFILE=$rootdir/tmp.$$
rsrcdir=$rootdir/resource
inteldir=/opt/intel
delOrder=(libsgx-enclave-common sgxdriver sgxsdk sgxssl)
installEnv=false
sgxssldir=""
sgxssl_openssl_source_dir=""
selfPID=$$
gotPkgNum=0
lockfile=$rootdir/lockfile
OSID=$(cat /etc/os-release | grep '^ID\b' | grep -Po "(?<==).*")
OSVERSION=$(cat /etc/os-release | grep 'VERSION_ID' | grep -Po "(?<==\").*(?=\")")
tmo=180
# Control configuration
instTimeout=30
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
declare -A checkArry="("$(for el in ${delOrder[@]}; do echo [$el]=0; done)")"

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

read -p "Please input your account password: " passwd
echo

# check if there is expect installed
which expect
if [ $? -ne 0 ]; then
    sudo apt-get install expect
    if [ $? -ne 0 ]; then
        verbose ERROR "Please install expect with root!"
        exit 1
    fi
fi

if checkSGXSDK; then
    ### Install sgx
    # install sgx sdk
    installSGXSDK
    
    # install sgx ssl
    #installSGXSSL
    
    # install openssl 
    #installOPENSSL
    
    # set environment
    setEnv
else
    verbose INFO "Dependencies have been installed!!!"
fi
