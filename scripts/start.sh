#!/bin/bash
function checkRes()
{
    local res=$1
    local err_op=$2
    local descriptor=$3

    if [ x"$descriptor" = x"" ] ; then 
        descriptor="&1"
    fi

    if [ $res -ne 0 ]; then
        eval "verbose ERROR "FAILED" t >$descriptor"
        case $err_op in 
            quit)       exit 1;;
            return)     return 1;;
            *)          ;;
        esac
        return 1
    fi

    eval "verbose INFO "SUCCESS" t >$descriptor"

    while [ -s $descriptor ]; do
        sleep 1
    done
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
        n)
            content="$time [$type] $info"
            ;;
        *)
            content="${color}$time [$type] $info${nc}"
    esac
    echo $opt $content
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
instdir=$(cd $basedir/..;pwd)
IPFS=$instdir/bin/ipfs
CRUST=$instdir/bin/crust
APPLOG=$instdir/log/crust.log
IPFSLOG=$instdir/log/ipfs.log
startType=$1

if [ x"$startType" != x"server" ]; then
    verbose INFO "Start crust in client Mode" n
    startType=""
else
    verbose INFO "Start crust in server Mode" n
fi

verbose INFO "Starting up IPFS..." h
ipfspid=$(ps -ef | grep ipfs | grep -v grep | awk '{print $2}')
if [ x"$ipfspid" != x"" ]; then
    kill -9 $ipfspid
    if [ $? -ne 0 ]; then
        # If failed by using current user, kill it using root
        execWithExpect "kill -9 $ipfspid"
    fi
fi
nohup $IPFS daemon &>$IPFSLOG &
checkRes $? "quit"

verbose INFO "Starting up crust..." h
sleep 3
nohup $CRUST $startType &>$APPLOG &
checkRes $? "quit"
