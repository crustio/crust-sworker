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
basedir=$basedir/..
srcdir=$basedir/src
pkgdir=$basedir/crust-tee
enclavefile="enclave.signed.so"
SYNCFILE=$basedir/.syncfile

. $basedir/scripts/utils.sh

true > $SYNCFILE

trap "success_exit" INT
trap "success_exit" EXIT

# Write version
cat $basedir/src/include/CrustStatus.h | grep "#define VERSION" | awk '{print $3}' | sed 's/"//g' > $basedir/VERSION
tee_version=$(cat $basedir/src/include/CrustStatus.h | grep "#define TEE_VERSION" | awk '{print $3}' | sed 's/"//g') 
echo "TEE=$tee_version" >> $basedir/VERSION

newversion=$(cat $basedir/VERSION | head -n 1)
verbose INFO "Start packaging tee, version is $newversion..."

# Create directory
rm -rf $pkgdir &>/dev/null
mkdir -p $pkgdir
mkdir -p $pkgdir/etc


# Install dependencies
$SUDO bash $basedir/scripts/install_deps.sh
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
verbose INFO "Tar tee..." h
res=0
tar -cvf crust-tee.tar $(basename $pkgdir) &> /dev/null
res=$(($?|$res))
checkRes $res "quit" "success"
