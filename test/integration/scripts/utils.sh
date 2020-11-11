#!/bin/bash
function crust_split()
{
    local filepath=$1
    local storepath=$2
    if [ ! -s "$filepath" ]; then
        verbose ERROR "File path is invalid!"
        return 1
    fi
    if [ ! -e "$storepath" ]; then
        verbose ERROR "Store path is not existed!"
        return 1
    fi
    # Generated dir name
    local detdir="dettmp.$(date +%N)"
    detdir=$storepath/$detdir
    mkdir -p $detdir
    local filename=$(basename $filepath)
    cp $filepath $detdir
    local oldfiledir=$(dirname $filepath)
    filepath=$detdir/$filename

    # Get block number
    local fz=$(wc -c < $filepath) 
    local blocknum=$((fz/1024/1024))
    if [ $((blocknum*1024*1024)) -lt $fz ]; then
        ((blocknum++))
    fi
    local suffixLen=${#blocknum}
    
    cd $detdir
    # Split file
    split -e -b 1m $filepath -d -a $suffixLen
    # Change file name
	ls | sed -n '/^x/p' | while read line; do 
        n=${line#*x}
        n=$(expr $n + 0)
        mv $line $n
    done
    # Get real file
    local i=0
    local mt_json="{\"size\":$fz,\"links_num\":$blocknum,\"links\":["
    local item=""
    local tmphash=""
    local totalhash=""
    while [ $i -lt $blocknum ]; do
        tmphash=$(cat $i | sha256sum | awk '{print $1}')
        totalhash="${totalhash}${tmphash}"
        item="{\"hash\":\"$tmphash\",\"size\":$(wc -c < $i),\"links_num\":0,\"links\":[]}"
        mt_json="${mt_json}${item}"
        if [ $((i+1)) -ne $blocknum ]; then
            mt_json="${mt_json},"
        fi
        mv $i ${i}_$tmphash
        ((i++))
    done
    totalhash=$(echo $totalhash | xxd -r -p | sha256sum | awk '{print $1}')
    mt_json="$mt_json],\"hash\":\"${totalhash}\"}"
    local newdetdir="$(dirname $detdir)/${totalhash}.${RANDOM}$(date +%N)"
    echo "$mt_json $newdetdir"
    cd - &>/dev/null
    rm $filepath
    mv $detdir $newdetdir
    rm -rf $detdir &>/dev/null
}

function get_workload()
{
    curl -s $baseurl/workload
}

function get_file_info()
{
    local hash="$1"
    curl -s -XGET $baseurl/file_info --data-raw "{\"hash\":\"$hash\"}"
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
    local tree=$1
    local path=$2

    curl -s -XPOST $baseurl/storage/seal --data-raw "{\"body\":$tree,\"path\":\"$path\"}"
}

function seal_file()
{
    local data_path=$1
    local store_path=$2
    local tmp_file=""
    if [ x"$tmpdir" = x"" ]; then
        tmp_file=tmp_file.${RANDOM}$(date +%N)
    else
        tmp_file=$tmpdir/tmp_file.${RANDOM}$(date +%N)
    fi

    ### Split file
    crust_split $data_path $store_path &>$tmp_file
    if [ $? -ne 0 ]; then
        rm $tmp_file
        return 1
    fi
    local mt_json=($(cat $tmp_file))

    ### Seal file block
    seal ${mt_json[0]} ${mt_json[1]} >$tmp_file
    if [ $? -ne 0 ]; then
        rm $tmp_file
        return 1
    fi

    cat $tmp_file
    rm $tmp_file
}

function unseal()
{
    local path=$1

    curl -s -XPOST $baseurl/storage/unseal --data-raw "{\"path\":\"$path\"}"
}

function confirm()
{
    local hash=$1

    curl -s -XPOST $baseurl/storage/confirm --data-raw "{\"hash\":\"$hash\"}"
}

function delete_file()
{
    local hash=$1

    curl -s -XPOST $baseurl/storage/delete --data-raw "{\"hash\":\"$hash\"}"
}

function srd_real()
{
    local change=$1

    curl -s -XPOST $baseurl/srd/change_real --data-raw "{\"change\":$change}"
}

function srd()
{
    local change=$1

    curl -s -XPOST $baseurl/srd/change --data-raw "{\"change\":$change}"
}

function srd_disk_change()
{
    local paths_json=$1
    local op=$2

    curl -s -XPOST $baseurl/srd/change_disk --data-raw "{\"paths\":$paths_json,\"op\":\"$op\"}"
}

function validate_srd_real()
{
    curl -s $baseurl/validate/srd_real
}

function validate_srd_bench()
{
    curl -s $baseurl/validate/srd
}

function validate_file()
{
    curl -s $baseurl/validate/file
}

function validate_file_real()
{
    curl -s $baseurl/validate/file_real
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

    validate_file &>/dev/null
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

function test_valid_file()
{
    local file_num=$1
    if [ x"$file_num" = x"" ]; then
        file_num=1000
    fi
    curl -s -XGET $baseurl/test/valid_file --data-raw "{\"file_num\":$file_num}"
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
    {
        verbose INFO "$info" n
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
    } >> $benchmarkfile
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
