#!/bin/bash
function showProcessInfo()
{
    if ! ps -ef | grep -v grep | grep -v ipfs | grep crust-tee &>/dev/null; then
        echo "TEE application doesn't run."
        return
    fi
    local monitorpid=$(cat $logfile | grep 'MonitorPID' | tail -n 1 | grep -Po "(?<==).*")
    local monitor2pid=$(cat $logfile | grep 'Monitor2PID' | tail -n 1 | grep -Po "(?<==).*")
    local workerpid=$(lsof -i :12222 | tail -n 1 | awk '{print $2}')

    if [ x"$monitorpid" = x"" ] || ! ps -ef | grep -v grep | grep $monitorpid &>/dev/null; then
        monitorpid="${HRED}stopped${NC}"
    else
        monitorpid="${HGREEN}$monitorpid${NC}"
    fi
    if [ x"$monitor2pid" = x"" ] || ! ps -ef | grep -v grep | grep $monitor2pid &>/dev/null; then
        monitor2pid="${HRED}stopped${NC}"
    else
        monitor2pid="${HGREEN}$monitor2pid${NC}"
    fi
    if [ x"$workerpid" = x"" ]; then
        workerpid="${HRED}stopped${NC}"
    else
        workerpid="${HGREEN}$workerpid${NC}"
    fi

    verbose INFO "Monitor  process pid: $monitorpid" n
    verbose INFO "Monitor2 process pid: $monitor2pid" n
    verbose INFO "Worker   process pid: $workerpid" n
}

function showPlotInfo()
{
    local tag=$1
    local para=$2

    if [ x"$tag" = x"status" ]; then
        curl $apiUrl/$tag
    elif [ x"$tag" = x"report" ]; then
        curl $apiUrl/$tag
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
CRUST=$instdir/bin/crust-tee
apiUrl=$(cat $conf | grep "\bapi_base_url\b" | grep -Po "(?=http).*(?=\")")

. $basedir/utils.sh

if [ x"$1" = x"" ]; then
    usage
fi

eval set -- `getopt -o prs --long plot,report,status -n 'Error' -- "$@"`

while true; do
    case "$1" in
        -p|--plot)
            showPlotInfo "status"
            shift
            ;;
        -r|--report)
            showPlotInfo "report"
            shift
            ;;
        -s|--status)
            showProcessInfo
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
