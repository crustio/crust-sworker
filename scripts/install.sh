#!/bin/bash
function checkOldCrustSworker()
{
    verbose INFO "Checking old crust sworker..." h
    local ret=0
    if [ ! -e "$crustdir/crust-sworker" ]; then
        verbose INFO "SUCCESS" t
        return
    fi
    cd $crustsworkerdir
    # Check version
    for dir in $(ls -d */ 2>/dev/null); do
        if [ -e $dir/VERSION ]; then
            if [ x"$(cat $dir/VERSION | head -n 1)" = x"$newversion" ]; then
                verbose ERROR "FAILED" t
                verbose ERROR "Same version $newversion has been installed!"
                exit 1
            fi
        fi
    done
    cd - &>/dev/null
    checkRes $ret "quit" "success"
}

function installAPP()
{
    # Create sworker directory
    verbose INFO "Creating sworker diretory related..." h
    local res=0
    mkdir -p $crustdir
    res=$(($?|$res))
    mkdir -p $crustsworkerdir
    res=$(($?|$res))
    mkdir -p $realsworkerdir
    res=$(($?|$res))
    mkdir -p $realsworkerdir/bin
    res=$(($?|$res))
    mkdir -p $realsworkerdir/etc
    res=$(($?|$res))
    mkdir -p $realsworkerdir/scripts
    res=$(($?|$res))
    checkRes $res "quit" "success"

    # Install sworker-app dependencies
    res=0
    cd $instdir
    make clean &>/dev/null
    if [ x"$build_mode" != x"" ]; then
        proddesc="in prod mode"
    else
        proddesc="in dev mode"
    fi
    setTimeWait "$(verbose INFO "Building and installing sworker application($proddesc)..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make $build_mode SIGN_CMD=$SIGN_CMD_FILE -j$((coreNum*2)) &>$ERRFILE
    checkRes $? "quit" "success" "$SYNCFILE"
    if [ x"$DOCKERMODLE" = x"1" ]; then
        rm $SIGN_CMD_FILE
    fi
    cd - &>/dev/null

    # Copy related files to install directory
    cp $srcdir/$appname $realsworkerdir/bin
    if [ ! -e "$instdir/etc/$enclaveso" ]; then
        cp $srcdir/$enclaveso $realsworkerdir/etc
    else
        cp $instdir/etc/$enclaveso $realsworkerdir/etc
    fi
    cp $srcdir/$configfile $realsworkerdir/etc
    cp $instdir/sgx_white_list_cert.bin $realsworkerdir/etc
    cp -r $instdir/scripts/uninstall.sh $realsworkerdir/scripts
    cp -r $instdir/scripts/utils.sh $realsworkerdir/scripts
    cp -r $instdir/VERSION $realsworkerdir

    # Generate template configure
    sed -i "s@<VERSION>@$newversion@g" $realsworkerdir/etc/$configfile

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
        if [ x"$(ps -ef | grep -v grep | grep $el | awk '{print $2}')" = x"$el" ]; then
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

    kill -- -$selfPID &>/dev/null
}

function usage()
{
    echo "Usage:"
		echo "    $0 -h                      Display this help message."
		echo "    $0 [options]"
    echo "Options:"
    echo "     -d for docker"
    echo "     -m build mode(dev or prod)"

	exit 1;
}

############## MAIN BODY ###############
# basic variable
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
### Import parameters {{{
. $basedir/utils.sh
### }}}
srcdir=$instdir/src
TMPFILE=$srcdir/tmp.$$
ERRFILE=$instdir/err.log
crustdir=/opt/crust
crustsworkerdir=$crustdir/crust-sworker
newversion=$(getVERSION)
realsworkerdir=$crustsworkerdir/$newversion
crusttooldir=$crustdir/tools
inteldir=/opt/intel
selfName=$(basename $0)
selfPID=$$
SYNCFILE=$instdir/.syncfile
res=0
uid=$(stat -c '%U' $instdir)
pad="$(printf '%0.1s' ' '{1..10})"
instSuccess=false
coreNum=$(cat /proc/cpuinfo | grep processor | wc -l)
# Control configuration
toKillPID=()
# App related
appname="crust-sworker"
enclaveso="enclave.signed.so"
configfile="Config.json"
# Crust related
crust_env_file=$realsworkerdir/etc/environment
SIGN_CMD_FILE=$instdir/scripts/prod_sign.sh

#trap "success_exit" INT
trap "success_exit" EXIT

# If get right version
if [ x"$newversion" = x"" ]; then
    verbose ERROR "Get wrong version:$newversion!"
    exit 1
fi

# Cmds
DOCKERMODLE=0
while getopts ":hdm:" opt; do
  case ${opt} in
    h )
		usage
      ;;
    d )
       DOCKERMODLE=1
      ;;
    m )
       build_mode=$OPTARG
      ;;
    \? )
      echo "Invalid Option: -$OPTARG" 1>&2
      exit 1
      ;;
  esac
done

if [ x"$build_mode" = x"prod" ]; then
    build_mode="SGX_DEBUG=0"
else
    build_mode=""
fi

if ps -ef | grep -v grep | grep $PPID | grep $selfName &>/dev/null; then
    selfPID=$PPID
fi

if [ $(id -u) -ne 0 ]; then
    verbose ERROR "Please run with sudo!"
    exit 1
fi

printf "%s%s\n"   "$pad" '                             __                _            __        ____'
printf "%s%s\n"   "$pad" '   ______      ______  _____/ /_____  _____   (_)___  _____/ /_____ _/ / /'
printf "%s%s\n"   "$pad" '  / ___/ | /| / / __ \/ ___/ //_/ _ \/ ___/  / / __ \/ ___/ __/ __ `/ / / '
printf "%s%s\n"   "$pad" ' (__  )| |/ |/ / /_/ / /  / ,< /  __/ /     / / / / (__  ) /_/ /_/ / / /  '
printf "%s%s\n\n" "$pad" '/____/ |__/|__/\____/_/  /_/|_|\___/_/     /_/_/ /_/____/\__/\__,_/_/_/   '

verbose INFO "Version -----------------$newversion-------------------"

disown -r

# check previous crust-sworker
checkOldCrustSworker

# Install Dependencies
if [ "$DOCKERMODLE" == "0" ]; then
    # Create denpendencies directory
    verbose INFO "Creating dependencies diretory related..." h
    res=0
    mkdir -p $crusttooldir
    res=$(($?|$res))
    mkdir -p $inteldir
    res=$(($?|$res))
    checkRes $res "quit" "success"

    # Install denpendencies
    bash $instdir/scripts/install_deps.sh
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

# Install Application
installAPP

if [ "$DOCKERMODLE" == "0" ]; then
    verbose INFO "Changing diretory owner..." h
    res=0
    chown -R $uid:$uid $crustsworkerdir
    res=$(($?|$res))
    chown -R $uid:$uid $crusttooldir
    res=$(($?|$res))
    checkRes $res "quit" "success"
fi

verbose INFO "Crust-sworker has been installed in /opt/crust/crust-sworker/$newversion!"
instSuccess=true
