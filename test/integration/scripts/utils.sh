#!/bin/bash
function get_workload()
{
    curl -s $baseurl/workload
}

function check_hash()
{
    local hash=$1
    local status=$2
    local -A status_m=([unconfirmed]=0 [valid]=1 [lost]=2 [deleted]=3)
    local file_info=$(get_file_info "$hash")
    if [ x"$file_info" = x"" ]; then
        if [ x"$status" = x"deleted" ]; then
            return 0
        else
            return 1
        fi
    fi
    if ! echo $file_info | jq '.' &>/dev/null; then
        return 1
    fi
    if [[ $(echo $file_info | jq '.status' | sed 's/"//g') =~ ^${status_m[$status]}[0-3]{2}$ ]]; then
        return 0
    fi

    return 1
}

function seal()
{
    local cid=$(add_file "$1")
    if [ x"${#cid}" != x"46" ]; then
        verbose ERROR "add file to IPFS failed!"
        return 1
    fi
    local ret_code=$(curl -s -XPOST $baseurl/storage/seal_sync --data-raw "{\"cid\":\"$cid\"}" -o /dev/null -w "%{http_code}")
    if [ ${ret_code} -eq 200 ]; then
        echo $cid
    else
        echo ""
    fi
}

function seal_by_cid()
{
    local cid=$1
    local ret_code=$(curl -s -XPOST $baseurl/storage/seal --data-raw "{\"cid\":\"$cid\"}" -o /dev/null -w "%{http_code}")
    if [ ${ret_code} -eq 200 ]; then
        echo $cid
    else
        echo ""
    fi
}

function add_file()
{
    local data_path="$1"
    curl -s -XPOST 'http://127.0.0.1:5001/api/v0/add'  --form "=@${data_path}" | jq '.Hash' | sed "s/\"//g"
}

function unseal()
{
    local path=$1

    curl -s -XPOST $baseurl/storage/unseal --data-raw "{\"path\":\"$path\"}"
}

function delete_file()
{
    local hash=$1

    local ret_code=$(curl -s -XPOST $baseurl/storage/delete_sync --data-raw "{\"cid\":\"$cid\"}" -o /dev/null -w "%{http_code}")
    if [ ${ret_code} -eq 200 ]; then
        return 0
    fi

    return 1
}

function delete_file_block_random()
{
    local rootcid=$1
    local file_info=$(get_file_info $rootcid)
    if ! echo $file_info | jq . &>/dev/null; then
        verbose ERROR "get file information failed!"
        return 1
    fi
    local block_num=$(echo $file_info | jq '.smerkletree|.links|length')
    if [ x"$block_num" = x"0" ]; then
        verbose ERROR "file($rootcid) block number is 0!"
        return 1
    fi
    for cid in $(echo $file_info | jq '.smerkletree|.links|.[]|.d_cid' | sed -n "${index}p" | sed "s/\"//g"); do
        if [ x"${#cid}" != x"46" ]; then
            verbose ERROR "get cid failed!"
            return 1
        fi
        local dskey=$($IPFS_HELPER $cid)
        if [ x"$dskey" = x"" ]; then
            verbose ERROR "get dskey from cid failed!"
            return 1
        fi
        find $ipfsdatadir -name "*${dskey}*" | xargs -I {} rm {}
    done
}

function get_file_info()
{
    curl -s -XPOST $baseurl/file/info --data-raw "{\"cid\":\"$1\"}"
}

function get_file_info_all()
{
    curl -s -XGET $baseurl/file/info_all
}

function srd_real_async()
{
    local change=$1

    local ret_code=$(curl -s -XPOST $baseurl/srd/change --data-raw "{\"change\":$change}" -o /dev/null -w "%{http_code}")
    if [ $ret_code -eq 200 ]; then
        return 0
    fi

    return 1
}

function srd_real_sync()
{
    local change=$1

    local ret_code=$(curl -s -XPOST $baseurl/srd/change_real --data-raw "{\"change\":$change}" -o /dev/null -w "%{http_code}")
    if [ $ret_code -eq 200 ]; then
        return 0
    fi

    return 1
}

function srd()
{
    local change=$1

    local ret_code=$(curl -s -XPOST $baseurl/srd/set_change --data-raw "{\"change\":$change}" -o /dev/null -w "%{http_code}")
    if [ $ret_code -eq 200 ]; then
        return 0
    fi

    return 1
}

function validate_add_proof()
{
    curl -s $baseurl/validate/add_proof
}

function validate_srd()
{
    curl -s $baseurl/validate/srd
}

function validate_srd_bench()
{
    curl -s $baseurl/validate/srd_bench
}

function validate_file()
{
    curl -s $baseurl/validate/file
}

function validate_file_bench()
{
    curl -s $baseurl/validate/file_bench
}

function report_work()
{
    local block_height=0
    if [ -s $reportheightfile ]; then
        block_height=$(cat $reportheightfile)
    fi
    ((block_height+=ERA_LENGTH))
    echo $block_height > $reportheightfile

    curl -s -XGET $baseurl/report/work --data-raw "{\"block_height\":$block_height}"
}

function report_work_result()
{
    curl -s $baseurl/report/result
}

function store_metadata()
{
    curl -s $baseurl/store_metadata
}

function test_add_file()
{
    local file_num=$1
    if [ x"$file_num" = x"" ]; then
        file_num=1000
    fi
    curl -s -XGET $baseurl/test/add_file --data-raw "{\"file_num\":$file_num}"
}

function test_lost_file()
{
    local file_num=$1
    if [ x"$file_num" = x"" ]; then
        file_num=1000
    fi
    curl -s -XGET $baseurl/test/lost_file --data-raw "{\"file_num\":$file_num}"
}

function test_delete_file()
{
    local file_num=$1
    if [ x"$file_num" = x"" ]; then
        file_num=1000
    fi
    curl -s -XGET $baseurl/test/delete_file --data-raw "{\"file_num\":$file_num}"
}

function test_delete_file_unsafe()
{
    local file_num=$1
    if [ x"$file_num" = x"" ]; then
        file_num=1000
    fi
    curl -s -XGET $baseurl/test/delete_file_unsafe --data-raw "{\"file_num\":$file_num}"
}

function clean_file()
{
    curl -s -XGET $baseurl/clean_file &>/dev/null
}

function is_number()
{
    local num=$1
    if ! [[ $num =~ ^[0-9]+$ ]]; then
        return 1
    fi
}

function kill_descendent()
{
    local pid=$1
    local cpid=""
    while : ; do
        cpid=$(ps -o pid= --ppid $pid)
        kill -9 $pid
        [ x"$cpid" = x"" ] && break
        pid=$cpid
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
            opt="-e"
            content="$time [$type] $info"
            ;;
        *)
            content="${color}$time [$type] $info${nc}"
    esac
    echo $opt "$content"
}

function benchmark_output()
{
    local info=$1
    local run_num=$2
    eval "declare -A ans_m="${3#*=}
    local key_arry=($4)
    local ans=0
    local c_sec=0
    local c_msec=0
    local ta=($(echo $info | grep -Po '\(.*\)' | sed "s/(\|)//g"))
    local sa=(8 12)
    info=$(echo "$info" | sed "s@(.*)@$(print_space ${sa[0]})${ta[0]}$(print_space ${sa[1]})${ta[1]}@g")
    sa[1]=$((${sa[1]}+${#ta[0]}))
    verbose INFO "$info" n > $benchmarkfile
    {
        if [ ${#key_arry[@]} -gt 0 ]; then
            for key in "${key_arry[@]}"; do
                ans=$((${ans_m["$key"]} / $run_num))
                c_sec=$(expr $ans / 1000000000)
                c_msec=$(expr $ans % 1000000)
                printf "%-${sa[0]}s%-$((${sa[1]}/3*2))s%-$((${sa[1]}/3))s%s\n" ' ' "$key" "--->" "${c_sec}.${c_msec}s"
            done
        else
            for key in "${!ans_m[@]}"; do
                ans=$((${ans_m["$key"]} / $run_num))
                c_sec=$(expr $ans / 1000000000)
                c_msec=$(expr $ans % 1000000)
                printf "%-${sa[0]}s%-$((${sa[1]}/3*2))s%-$((${sa[1]}/3))s%s\n" ' ' "$key" "--->" "${c_sec}.${c_msec}s"
            done
        fi
        echo -e "\n"
    } | grep -v "^$" | sort -t : -k 1n -k 2h >> $benchmarkfile
}

function get_config()
{
    local exp=$1
    if [ ! -s "$configfile" ]; then
        verbose ERROR "config file:$configfile isn't existed!" >&2
        return 1
    fi
    cat $configfile | jq "$exp" | sed ':a;N;s/\n//g;ta' | sed 's/^"\|"$//g'
}

function print_space()
{
    printf " %.0s" $(eval "echo {1..$1}")
}

function print_title()
{
    local info=$1
    local len=${#info}
    local sp=40
    local time="[$(date "+%Y/%m/%d %T.%3N")] [INFO] "
    printf "%s #####%$((sp/2))s%-$((sp/2))s#####\n" "$time" "`echo $info | cut -c 1-$(($len/2))`" "`echo $info | cut -c $(($len/2+1))-$len`"
}

function parse_json_array()
{
    local array=$1
    echo ${array:1:${#array}-2} | sed -e 's/,/ /g' -e 's/"//g'
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
                verbose ERROR "Unexpected error occurs!"
                exit 1
                ;;
            return)     
                return 1
                ;;
            *)  ;;
        esac
    fi
}

# color
RED='\033[0;31m'
HRED='\033[1;31m'
GREEN='\033[0;32m'
HGREEN='\033[1;32m'
YELLOW='\033[0;33m'
HYELLOW='\033[1;33m'
NC='\033[0m'
