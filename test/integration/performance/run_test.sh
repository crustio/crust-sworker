#!/bin/bash
function _seal()
{
    echo 0 > $sealsyncfile
    file_num_g=0
    local total_num=$(get_config ".performance|.file_num")
    while true; do
        if [ $file_num_g -lt $total_num ]; then
            local num=800
            while [ $num -ge 0 ]; do
                _seal_r
                ((num--))
            done
        fi
    done
}

function _seal_r()
{
    local file_path=$ptmpdir/1m.$(date +%N)$RANDOM
    $scriptdir/gen_random.sh 1m $file_path &>/dev/null
    if [ $? -ne 0 ]; then
        rm -rf $file_path &>/dev/null
        return 1
    fi
    local tmpfile=${TMPFILE}${RANDOM}$(date +%N)
    seal_file $file_path $testfiledir &>$tmpfile
    if [ $? -eq 0 ]; then
        local ret_body=$(cat $tmpfile)
        local sealed_hash=$(echo $ret_body | jq '.path' | sed 's/"//g' | xargs -I {} basename {} 2>/dev/null)
        #verbose INFO "sealing hash:$sealed_hash..." h
        if [ x"$sealed_hash" != x"" ] && [ ${#sealed_hash} -eq 64 ]; then
            #verbose INFO "success" t
            echo 0 > $sealtmpdir/$sealed_hash
            res_inc "seal" "success" $sealresfile
            ((file_num_g++))
        else
            #verbose ERROR "failed" t
            res_inc "seal" "failed" $sealresfile
        fi
    else
        res_inc "seal" "failed" $sealresfile
    fi
    rm -rf $file_path
    rm -rf $tmpfile
}

function _unseal()
{
    while true; do
        sleep $(($deletetime + $RANDOM % 30))
        (
          flock -w 30 201
          local sealed_hashs=($(ls $confirmtmpdir))
          if [ ${#sealed_hashs[@]} -eq 0 ]; then
              continue
          fi
          local num=$(($RANDOM % ${#sealed_hashs[@]}))
          if [ $num -gt $deletefilethres ]; then
              num=$deletefilethres
          fi
          while [ $num -ge 0 ]; do
              _unseal_r $testfiledir/${sealed_hashs[$num]}
              ((num--))
          done
        ) 201>$deletelockfile
    done
}

function _unseal_r()
{
    local path=$1
    local hash=$(basename $path)
    #verbose INFO "unsealing hash:$hash..." h
    unseal $path &>$UNSEALTMPFILE
    if [ $? -eq 0 ]; then
        #verbose INFO "success" t
        delete_file $hash &>/dev/null
        rm -rf $sealtmpdir/$hash
        rm -rf $(cat $UNSEALTMPFILE)
        res_inc "unseal" "success" $unsealresfile
    else
        #verbose ERROR "failed" t
        res_inc "unseal" "failed" $unsealresfile
    fi
}

function _srd()
{
    local srd_paths=$(get_config ".performance|.srd_paths")
    local srd_total=$(get_config ".performance|.srd_num")
    srd_disk_change "$srd_paths" "add"
    local srd_num=0
    local srd_per_turn=900
    while true; do
        sleep $((3 + $RANDOM % 5))
        if [ $srd_num -lt $srd_total ]; then
            srd $srd_per_turn &>/dev/null
            if [ $? -eq 0 ]; then
                res_inc "srd" "success" $srdresfile
            else
                res_inc "srd" "failed" $srdresfile
            fi
            ((srd_num+=srd_per_turn))
        fi
        local tmp_num=$(get_workload | jq '.srd|.space' 2>/dev/null)
        if [[ $tmp_num =~ ^[1-9][0-9]*$ ]]; then
            srd_num=$tmp_num
        fi
    done
}

function _validate
{
    while true; do
        sleep 10
        validate_file &>/dev/null
        validate_srd &>/dev/null
        store_metadata &>/dev/null
        res_inc "confirm" "success" $validateresfile
    done
}

function _confirm()
{
    while true; do
        sleep $((5 + $RANDOM % 10))
        local sealed_hashs=($(ls $sealtmpdir))
        if [ ${#sealed_hashs[@]} -eq 0 ]; then
            continue
        fi
        local num=$(($RANDOM % ${#sealed_hashs[@]}))
        while [ $num -ge 0 ]; do
              _confirm_r ${sealed_hashs[$num]}
              ((num--))
        done
    done
}

function _confirm_r()
{
    local hash=$1
    #verbose INFO "confirming hash:$hash..." h
    confirm $hash &>/dev/null
    if [ $? -eq 0 ]; then
        #verbose INFO "success" t
        mv $sealtmpdir/$hash $confirmtmpdir
        res_inc "confirm" "success" $confirmresfile
    else
        #verbose ERROR "failed" t
        res_inc "confirm" "failed" $confirmresfile
    fi
}

function _delete()
{
    while true; do
        sleep $(($deletetime + $RANDOM % 30))
        (
          flock -w 30 201
          local sealed_hashs=($(ls $confirmtmpdir))
          if [ ${#sealed_hashs[@]} -eq 0 ]; then
              continue
          fi
          local num=$(($RANDOM % ${#sealed_hashs[@]}))
          if [ $num -gt $deletefilethres ]; then
              num=$deletefilethres
          fi
          while [ $num -ge 0 ]; do
              _delete_r ${sealed_hashs[$num]}
              ((num--))
          done
        ) 201>$deletelockfile
    done
}

function _delete_r()
{
    local hash=$1
    delete_file $hash &>/dev/null
    if [ $? -eq 0 ]; then
        rm $confirmtmpdir/$hash
        rm -rf $testfiledir/$hash
        res_inc "delete" "success" $deleteresfile
    else
        res_inc "delete" "failed" $deleteresfile
    fi
}

function _workreport()
{
    local lfile=workreport
    local tag=0
    while true; do
        sleep $((20 + $RANDOM % 10))
        report_work &>$instdir/${lfile}.$tag
        if [ $? -eq 0 ]; then
            res_inc "report" "success" $reportresfile
        else
            res_inc "report" "failed" $reportresfile
        fi
        ((tag=(tag+1)%2))
    done
}

function show_info()
{
cat << EOF >$TMPFILE
{
    "seal":{"success":$(get_success $sealresfile),"failed":$(get_failed $sealresfile)},
    "unseal":{"success":$(get_success $unsealresfile),"failed":$(get_failed $unsealresfile)},
    "confirm":{"success":$(get_success $confirmresfile),"failed":$(get_failed $confirmresfile)},
    "delete":{"success":$(get_success $deleteresfile),"failed":$(get_failed $deleteresfile)},
    "srd":{"success":$(get_success $srdresfile),"failed":$(get_failed $srdresfile)},
    "validate":{"success":$(get_success $validateresfile),"failed":$(get_failed $validateresfile)},
    "workreport":{"success":$(get_success $reportresfile),"failed":$(get_failed $reportresfile)}
}
EOF
    cat $TMPFILE | jq '.'
}

function res_inc()
{
    local desc=$1
    local type=$2
    local file=$3
    desc=${desc}des
    (
      flock -w 20 200
      if [ ! -e "$file" ]; then
          echo -e "0\n0" > $file
      fi
      if [ x"$type" = x"success" ]; then
          local num=$(cat $file | head -n 1)
          ((num++))
          sed -i "1 c $num" $file &>/dev/null
      elif [ x"$type" = x"failed" ]; then
          local num=$(cat $file | tail -n 1)
          ((num++))
          sed -i "2 c $num" $file &>/dev/null
      fi
    ) 200>$ptmpdir/$desc
}

function get_success()
{
    local file=$1
    if [ -e $file ]; then
        cat $file | head -n 1
    else
        echo 0
    fi
}

function get_failed()
{
    local file=$1
    if [ -e $file ]; then
        cat $file | tail -n 1
    else
        echo 0
    fi
}

function kill_process()
{
    for pid in ${name2pid_m[@]}; do
        kill -9 $pid &>/dev/null
    done
}

function seal_exit()
{
    rm $TMPFILE
    rm -rf $sealtmpdir
    rm -rf $testfiledir
    rm -rf $ptmpdir
}

########## MAIN BODY ##########
# basic variable
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
scriptdir=$instdir/scripts
datadir=$instdir/data
tmpdir=$instdir/tmp
sealtmpdir=$tmpdir/seal
confirmtmpdir=$tmpdir/confirmed
testdir=$instdir/test_app
testfiledir=$testdir/files
configfile=$instdir/config/config.json
TMPFILE=$basedir/TMPFILE
UNSEALTMPFILE=$tmpdir/unseal.tmp
ptmpdir=$instdir/performance/tmp
# Result file
sealresfile=$ptmpdir/seal_info
unsealresfile=$ptmpdir/unseal_info
reportresfile=$ptmpdir/report_info
deleteresfile=$ptmpdir/delete_info
confirmresfile=$ptmpdir/confirm_info
validateresfile=$ptmpdir/validate_info
srdresfile=$ptmpdir/srd_info
deletefilethres=3
deletetime=100
deletelockfile=$ptmpdir/deletelockfile
<<<<<<< HEAD
seallockfile=$ptmpdir/seallockfile
sealsyncfile=$ptmpdir/sealsyncfile
=======
sealsyncdir=$ptmpdir/sealsyncdir
>>>>>>> dev

# Control sig num
sigShowInfo=28

trap 'kill_process' INT
trap 'seal_exit' EXIT
trap 'show_info' $sigShowInfo

. $scriptdir/utils.sh

mkdir -p $sealtmpdir
mkdir -p $confirmtmpdir
mkdir -p $ptmpdir
mkdir -p $sealsyncdir

declare -A name2pid_m

spid=$1
pid=$$
data_arry=(1m)
data_size=${#data_arry[@]}

verbose INFO "current pid: $pid " n

# Randomly seal file
_seal &
name2pid_m[_sealpid]=$!
# Randomly unseal
_unseal &
name2pid_m[_unseal]=$!
# Randomly srd
_srd &
name2pid_m[_srdpid]=$!
# Randomly confirm
_confirm &
name2pid_m[_confirmpid]=$!
# Randomly delete
_delete &
name2pid_m[_delete]=$!
# Randomly validate
_validate &
name2pid_m[_validatepid]=$!
# Randomly report work
_workreport &
name2pid_m[_workreport]=$!

while true; do
    if [[ $spid =~ ^[1-9][0-9]*$ ]]; then
       if ! ps -ef | grep $spid | awk '{print $2}' | grep $spid &>/dev/null; then
           show_info
           kill_process
           break
       fi
    fi
    sleep 5
done
