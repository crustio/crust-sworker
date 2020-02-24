#!/bin/bash
############## MAIN BODY ###############
# basic variable
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
IPFS=$instdir/bin/ipfs
CRUSTTEE=$instdir/bin/crust-tee
APPLOG=$instdir/log/crust.log
IPFSLOG=$instdir/log/ipfs.log
startType=$1

. $basedir/utils.sh
. $instdir/etc/environment

if [ x"$startType" != x"server" ]; then
    verbose INFO "Start crust-tee in client Mode" n
    startType=""
else
    verbose INFO "Start crust-tee in server Mode" n
fi

verbose INFO "Starting up IPFS..." h
ipfspid=$(ps -ef | grep ipfs | grep -v grep | awk '{print $2}')
if [ x"$ipfspid" != x"" ]; then
    kill -9 $ipfspid
    if [ $? -ne 0 ]; then
        # If failed by using current user, kill it using root
        sudo kill -9 $ipfspid
    fi
fi
nohup $IPFS daemon &>$IPFSLOG &
checkRes $? "quit"

verbose INFO "Starting up crust-tee..." h
sleep 3
nohup $CRUSTTEE $startType &>$APPLOG &
checkRes $? "quit"
