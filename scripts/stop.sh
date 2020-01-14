#!/bin/bash
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
instdir=$(cd $basedir/..;pwd)
killIPFS=true

. $basedir/utils.sh


verbose INFO "Shutting down IPFS..." h
ipfspid=$(ps -ef | grep ipfs | grep -v grep | awk '{print $2}')
if [ x"$ipfspid" != x"" ]; then
    kill -9 $ipfspid
    if [ $? -ne 0 ]; then
        # If failed by using current user, kill it using root
        execWithExpect "kill -9 $ipfspid"
        if [ $? -ne 0 ]; then
            verbose INFO "FAILED" t
            killIPFS=false
        fi
    fi
fi
$killIPFS && verbose INFO "SUCCESS" t

verbose INFO "Shutting down crust..." h
ps -ef | grep -v grep | grep "bin/crust" | awk '{print $2}' | xargs -I {} kill -9 {}
checkRes $? "quit"
