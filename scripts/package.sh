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

# TODO: optimze package flow
############## MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
appdir=$instdir/Miner
VERSION=$(cat $instdir/VERSION)
pkgdir=$instdir/crust-$VERSION
enclavefile="enclave.signed.so"
SYNCFILE=$instdir/.syncfile
resourceUrl="ftp://47.102.98.136/pub/resource.tar"


. $basedir/utils.sh

trap "success_exit" INT
trap "success_exit" EXIT

mkdir -p $pkgdir

# Check if resource and bin directory exsited
cd $instdir
if [ ! -e "$instdir/bin" ] || [ ! -e "$instdir/resource" ]; then
    verbose INFO "This is your first packing, some resource should be downloaded, please wait..."
    wget $resourceUrl
    if [ $? -ne 0 ]; then
        verbose ERROR "Download failed!"
        exit 1
    fi
    tar -xvf $(basename $resourceUrl) &>/dev/null
    if [ $? -ne 0 ]; then
        verbose ERROR "Unpack failed, bad package!"
        exit 1
    fi
    rm -r $(basename $resourceUrl)
fi
cd -

# Generate mrenclave file
if [ x"$1" != x"debug" ]; then
    cd $appdir
    setTimeWait "$(verbose INFO "Building MRENCLAVE file..." h)" $SYNCFILE &
    toKillPID[${#toKillPID[*]}]=$!
    make clean && make &>/dev/null
    checkRes $? "quit" "$SYNCFILE"
    cp $enclavefile $instdir/etc
    make clean
    cd -
fi

cd $instdir
cp -r bin etc log Miner resource scripts $pkgdir
cp LICENSE README.md VERSION $pkgdir
rm etc/$enclavefile
cd -

cd $pkgdir
rm scripts/package.sh
mv scripts/install.sh ./
cd -

cd $instdir
tar -cvf crust-$VERSION.tar crust-$VERSION
cd -
