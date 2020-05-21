#!/bin/bash
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
    checkRes $ret "quit" "success"
}

function installAPP()
{
    # Install tee-app dependencies
    local res=0
    cd $appdir
    make clean &>/dev/null
    setTimeWait "$(verbose INFO "Installing application..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make -j$((coreNum*2)) &>$ERRFILE
    checkRes $? "quit" "success" "$SYNCFILE"
    mkdir -p ../bin
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
    source $crust_env_file
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

function printEnd_success()
{
    printf "%s%s\n"   "$pad" '    _            __        ____                  __'
    printf "%s%s\n"   "$pad" '   (_)___  _____/ /_____ _/ / /  ___  ____  ____/ /'
    printf "%s%s\n"   "$pad" '  / / __ \/ ___/ __/ __ `/ / /  / _ \/ __ \/ __  / '
    printf "%s%s\n"   "$pad" ' / / / / (__  ) /_/ /_/ / / /  /  __/ / / / /_/ /  '
    printf "%s%s\n\n" "$pad" '/_/_/ /_/____/\__/\__,_/_/_/   \___/_/ /_/\__,_/   '
}

function printEnd_failed()
{
    printf "%s${HRED}%s${NC}\n"   "$pad" '    _            __        ____   ____      _ __         __'
    printf "%s${HRED}%s${NC}\n"   "$pad" '   (_)___  _____/ /_____ _/ / /  / __/___ _(_) /__  ____/ /'
    printf "%s${HRED}%s${NC}\n"   "$pad" '  / / __ \/ ___/ __/ __ `/ / /  / /_/ __ `/ / / _ \/ __  / '
    printf "%s${HRED}%s${NC}\n"   "$pad" ' / / / / (__  ) /_/ /_/ / / /  / __/ /_/ / / /  __/ /_/ /  '
    printf "%s${HRED}%s${NC}\n\n" "$pad" '/_/_/ /_/____/\__/\__,_/_/_/  /_/  \__,_/_/_/\___/\__,_/   '
}

function success_exit()
{
    rm -f $TMPFILE &>/dev/null

    rm -f $SYNCFILE &>/dev/null

    # Kill alive useless sub process
    for el in ${toKillPID[@]}; do
        if ps -ef | grep -v grep | grep $el &>/dev/null; then
            kill -9 $el &>/dev/null
        fi
    done

    # Print end session
    if $instSuccess; then
        printEnd_success
    else
        echo
        printEnd_failed
    fi

    kill -- -$selfPID
}

############## MAIN BODY ###############
# basic variable
basedir=$(cd `dirname $0`;pwd)
appdir=$basedir/src
instdir=$basedir
TMPFILE=$appdir/tmp.$$
ERRFILE=$basedir/err.log
crustdir=/opt/crust
crustteedir=$crustdir/crust-tee
crusttooldir=$crustdir/tools
inteldir=/opt/intel
selfName=$(basename $0)
selfPID=$$
SYNCFILE=$instdir/.syncfile
res=0
uid=$(stat -c '%U' $basedir)
pad="$(printf '%0.1s' ' '{1..10})"
instSuccess=false
coreNum=$(cat /proc/cpuinfo | grep processor | wc -l)
# Control configuration
toKillPID=()
# App related
appname="crust-tee"
enclaveso="enclave.signed.so"
configfile="Config.json"
# Crust related
crust_env_file=$crustteedir/etc/environment


. $basedir/scripts/utils.sh

#trap "success_exit" INT
trap "success_exit" EXIT


if ps -ef | grep -v grep | grep $PPID | grep $selfName &>/dev/null; then
    selfPID=$PPID
fi

if [ $(id -u) -ne 0 ]; then
    verbose ERROR "Please run with sudo!"
    exit 1
fi



printf "%s%s\n"   "$pad" '                        __     __               _            __        ____'
printf "%s%s\n"   "$pad" '  ____________  _______/ /_   / /____  ___     (_)___  _____/ /_____ _/ / /'
printf "%s%s\n"   "$pad" ' / ___/ ___/ / / / ___/ __/  / __/ _ \/ _ \   / / __ \/ ___/ __/ __ `/ / / '
printf "%s%s\n"   "$pad" '/ /__/ /  / /_/ (__  ) /_   / /_/  __/  __/  / / / / (__  ) /_/ /_/ / / /  '
printf "%s%s\n\n" "$pad" '\___/_/   \__,_/____/\__/   \__/\___/\___/  /_/_/ /_/____/\__/\__,_/_/_/   '


# Uninstall previous crust-tee
uninstallOldCrustTee

# Create directory
verbose INFO "Creating and setting diretory related..." h
res=0
mkdir -p $crustdir
res=$(($?|$res))
mkdir -p $crusttooldir
res=$(($?|$res))
mkdir -p $crustteedir
res=$(($?|$res))
mkdir -p $inteldir
res=$(($?|$res))
checkRes $res "quit" "success"

# Install Dependencies
bash $basedir/scripts/install_deps.sh
if [ $? -ne 0 ]; then
    exit 1
fi

# Install Application
installAPP

verbose INFO "Changing diretory owner..." h
res=0
chown -R $uid:$uid $crustteedir
res=$(($?|$res))
chown -R $uid:$uid $crusttooldir
res=$(($?|$res))
checkRes $res "quit" "success"

verbose INFO "Crust-tee has been installed in /opt/crust/crust-tee! Go to /opt/crust/crust-tee and follow README to start crust."

instSuccess=true
