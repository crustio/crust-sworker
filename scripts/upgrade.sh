#!/bin/bash

function get_json_value()
{
  local json=$1
  local key=$2

  if [[ -z "$3" ]]; then
    local num=1
  else
    local num=$3
  fi

  local value=$(echo "${json}" | awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'${key}'\042/){print $(i+1)}}}' | tr -d '"' | sed -n ${num}p)

  echo ${value}
}

scriptdir=$(cd `dirname $0`;pwd)
basedir=$(cd $scriptdir/..;pwd)

while :
do
system_health=`curl http://$1/api/v1/system/health 2>/dev/null`
if [ x"$system_health" = x"" ]; then
    echo "please run crust chain and api"
    sleep 10
    continue
fi

is_syncing=`get_json_value $system_health isSyncing`
if [ x"$is_syncing" == x"" ]; then
    echo "crust api dose not connet to crust chain"
    sleep 10
    continue
fi

if [ x"$is_syncing" == x"true" ]; then
    echo "crust chain is syncing"
    sleep 10
    continue
fi

code=`curl http://$1/api/v1/tee/code 2>/dev/null`
if [ x"$code" = x"" ]; then
    echo "please run chain and api"
    sleep 10
    continue
fi
echo "sWorker code on chain: $code"

id_info=`curl http://$2/api/v0/enclave/id_info 2>/dev/null`
if [ x"$id_info" = x"" ]; then
    echo "please run sworker"
    sleep 10
    continue
fi

id_info=`echo $id_info | sed 's/ //g'`
mrenclave=`get_json_value $id_info mrenclave`
if [ x"$mrenclave" = x"" ]; then
    echo "waiting sworker ready"
    sleep 10
    continue
fi

echo "sWorker self code: $mrenclave"

if [ x"$mrenclave" != x"$code" ]; then
    echo "Upgrade..."
fi

sleep 10
done
