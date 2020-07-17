#!/bin/bash
function checkRes()
{
    ### receive 4 parameters at most:
    ### $1 : Command execution result
    ### $2 : Should be "return" or "quit", 
    ###      which means if command failed, function returns or process exits
    ### $3 : Success information, which means if command executes successfully, print this info
    ### $4 : Output stream, default is standard output stream
    local res=$1
    local err_op=$2
    local tag=$3
    local descriptor=$4
    local tagfailed=""
    local tagsuccess=""

    if [ x"$descriptor" = x"" ] ; then 
        descriptor="&1"
    fi

    if [ x"$tag" = x"yes" ]; then
        tagsuccess="yes"
        tagfailed="no"
    elif [ x"$tag" = x"success" ]; then
        tagsuccess="success"
        tagfailed="failed"
    fi

    if [ $res -ne 0 ]; then
        eval "verbose ERROR "$tagfailed" t >$descriptor"
    else
        eval "verbose INFO "$tagsuccess" t >$descriptor"
    fi

    while [ -s "$descriptor" ]; do
        sleep 1
    done

    if [ $res -ne 0 ]; then
        case $err_op in
            quit)       
                verbose ERROR "Unexpected error occurs!Please check $ERRFILE for details!"
                exit 1
                ;;
            return)     
                return 1
                ;;
            *)  ;;
        esac
    fi
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
    local time="[$(date "+%Y/%m/%d %T.%3N")]"

    case $type in
        ERROR)  color=$HRED ;;
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

function setTimeWait()
{
    ### Be careful that this function should be used with checkRes function!
    local info=$1
    local syncfile=$2
    local acc=1
    while [ ! -s "$syncfile" ]; do
        printf "%s\r" "${info}${acc}s"
        ((acc++))
        sleep 1
    done

    echo "${info}$(cat $syncfile)"
    true > $syncfile
}

# Be careful about this function
function getVERSION()
{
    local basedir=$(cd `dirname $0`;pwd)
    local srcdir=$(cd $basedir/../src;pwd)
    echo $(cat $srcdir/include/Resource.h | grep "#define VERSION" | awk '{print $3}' | sed 's/"//g' 2>/dev/null)
}

# Be careful about this function
function getTEEVERSION()
{
    local basedir=$(cd `dirname $0`;pwd)
    local srcdir=$(cd $basedir/../src;pwd)
    echo $(cat $srcdir/enclave/Parameter.h | grep "#define TEE_VERSION" | awk '{print $3}' | sed 's/"//g' 2>/dev/null) 
}

# color
RED='\033[0;31m'
HRED='\033[1;31m'
GREEN='\033[0;32m'
HGREEN='\033[1;32m'
YELLOW='\033[0;33m'
HYELLOW='\033[1;33m'
NC='\033[0m'
