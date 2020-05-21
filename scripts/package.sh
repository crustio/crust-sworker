#!/bin/bash
function success_exit()
{
    rm -f $SYNCFILE &>/dev/null

    # Kill alive useless sub process
    for el in ${toKillPID[@]}; do
        if ps -ef | grep -v grep | grep $el &>/dev/null; then
            kill -9 $el
        fi
    done

    rm -rf $pkgdir
}

############## MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
appdir=$instdir/src
VERSION=$(cat $instdir/VERSION)
pkgdir=$instdir/crust-tee
enclavefile="enclave.signed.so"
SYNCFILE=$instdir/.syncfile
sgxsdkdir="/opt/intel/sgxsdk"
sgxssldir="/opt/intel/sgxssl"


. $basedir/utils.sh

trap "success_exit" INT
trap "success_exit" EXIT

rm -rf $pkgdir &>/dev/null
mkdir -p $pkgdir

# Check if resource exsited
cd $instdir
if [ ! -e "$instdir/resource" ]; then
    verbose ERROR "Need resource to install environment, please go to https://github.com/crustio/crust-tee/releases to download the latest crust-tee.tar and find resource in it"
    exit 1
fi
cd -

# Generate mrenclave file
mkdir $instdir/etc
mkdir $instdir/bin
if [ x"$1" != x"debug" ]; then
    if [ ! -d "$sgxsdkdir" ] || [ ! -d "$sgxssldir" ]; then
        # Install dependencies
        bash $basedir/install_deps.sh
        if [ $? -ne 0 ]; then
            verbose ERROR "Install dependencies failed!"
            exit 1
        fi
    fi

    cd $appdir
    setTimeWait "$(verbose INFO "Building enclave.signed.so file..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make clean && make &>/dev/null
    checkRes $? "quit" "$SYNCFILE"
    cp $enclavefile $instdir/etc
    make clean
    cd -
else
    cd $appdir
    make clean
    cd -
fi

cd $instdir
cp -r bin etc log src resource scripts $pkgdir
cp LICENSE README.md VERSION buildenv.mk $pkgdir
rm -rf etc bin
cd -

cd $pkgdir
rm scripts/package.sh
mv scripts/install.sh ./
cd -

cd $instdir
tar -cvf crust-tee-$VERSION.tar $(basename $pkgdir)
cd -
