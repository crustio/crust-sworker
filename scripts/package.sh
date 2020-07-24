#!/bin/bash
SUDO=''
if (( $EUID != 0 )); then
  SUDO='sudo'
fi

function success_exit()
{
    rm -f $SYNCFILE &>/dev/null

    # Kill alive useless sub process
    for el in ${toKillPID[@]}; do
        if [ x"$(ps -ef | grep -v grep | grep $el | awk '{print $2}')" = x"$el" ]; then
            kill -9 $el
        fi
    done

    rm -rf $pkgdir &>/dev/null
}

############## MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
srcdir=$instdir/src
pkgdir=$instdir/crust-sworker
enclavefile="enclave.signed.so"
SYNCFILE=$instdir/.syncfile

. $instdir/scripts/utils.sh

true > $SYNCFILE

trap "success_exit" INT
trap "success_exit" EXIT

# Write version
getVERSION > $instdir/VERSION
echo "TEE=$(getTEEVERSION)" >> $instdir/VERSION

newversion=$(cat $instdir/VERSION | head -n 1)
verbose INFO "Start packaging sworker, version is $newversion..."

# Create directory
rm -rf $pkgdir &>/dev/null
mkdir -p $pkgdir
mkdir -p $pkgdir/etc

# Install dependencies
$SUDO bash $instdir/scripts/install_deps.sh
if [ $? -ne 0 ]; then
    verbose ERROR "Install dependencies failed!"
    exit 1
fi

# Generate mrenclave file
setTimeWait "$(verbose INFO "Building enclave.signed.so file..." h)" $SYNCFILE &
toKillPID[${#toKillPID[*]}]=$!
make clean && make -j4 &>/dev/null
checkRes $? "quit" "success" "$SYNCFILE"
cp $srcdir/$enclavefile $pkgdir/etc
make clean

cp -r src resource scripts test $pkgdir
cp Makefile VERSION buildenv.mk $pkgdir

# Tar
verbose INFO "Tar sworker..." h
res=0
tar -cvf crust-sworker.tar $(basename $pkgdir) &> /dev/null
res=$(($?|$res))
checkRes $res "quit" "success"
