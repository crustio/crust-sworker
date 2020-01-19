#!/bin/bash
function showProcessInfo()
{
    if ! ps -ef | grep -v grep | grep -v ipfs | grep crust &>/dev/null; then
        echo "TEE application doesn't run."
        return
    fi
    local monitorpid=$(cat $logfile | grep 'MonitorPID' | tail -n 1 | grep -Po "(?<==).*")
    local monitor2pid=$(cat $logfile | grep 'Monitor2PID' | tail -n 1 | grep -Po "(?<==).*")
    local workerpid=$(cat $logfile | grep 'WorkerPID' | tail -n 1 | grep -Po "(?<==).*")

    echo "Monitor  process pid: $monitorpid"
    echo "Monitor2 process pid: $monitor2pid"
    echo "Worker   process pid: $workerpid"
}

function showPlotInfo()
{
    local tag=$1
    local para=$2

    if [ x"$tag" = x"status" ]; then
        curl $apiUrl/$tag
    elif [ x"$tag" = x"report" ]; then
        curl $apiUrl/$tag\?block_hash\=$para
    fi

    echo
}

function usage()
{
cat << EOF
    status.sh <option> <argument>
        option:
            -p,--plot   show plot disk information
            -r,--report show plot disk report information,need block hash as argument
            -s,--status show TEE application process information
EOF
}

############### MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
conf=$instdir/etc/Config.json
logfile=$instdir/log/crust.log
CRUST=$instdir/bin/crust
apiUrl=$(cat $conf | grep "apiBaseUrl" | grep -Po "(?=http).*(?=\")")

. $basedir/utils.sh

eval set -- `getopt -o pr:s --long plot,report:,status -n 'Error' -- "$@"`

while true; do
    case "$1" in
        -p|--plot)
            showPlotInfo "status"
            shift
            ;;
        -r|--report)
            showPlotInfo "report" "$2"
            shift 2
            ;;
        -s|--status)
            showProcessInfo "report"
            shift
            ;;
        --)
            shift
            break;;
        *)
            usage
            exit 1
            ;;
    esac
done
