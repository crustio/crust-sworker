#!/bin/bash
function checkRes()
{
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

# color
RED='\033[0;31m'
HRED='\033[1;31m'
GREEN='\033[0;32m'
HGREEN='\033[1;32m'
YELLOW='\033[0;33m'
HYELLOW='\033[1;33m'
NC='\033[0m'
