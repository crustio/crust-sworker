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

# TODO: optimze package flow
############## MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$basedir/..
appdir=$instdir/Miner
VERSION=$(cat $instdir/VERSION)
pkgdir=$instdir/crust-$VERSION
enclavefile="enclave.signed.so"

mkdir -p $pkgdir

# Generate mrenclave file
cd $appdir
verbose INFO "Building MRENCALVE file..." h
make clean && make &>/dev/null
checkRes $? "quit"
cp $enclavefile $instdir/etc
make clean
cd -

cd $instdir
cp -r bin etc log Miner resource scripts $pkgdir
cp LICENSE README.md VERSION $pkgdir
rm etc/$enclavefile
cd -

cd $pkgdir
rm scripts/package.sh
mv scripts/install.sh ./
cd -

tar -cvf crust-$VERSION.tar $pkgdir/*

rm -rf $pkgdir
