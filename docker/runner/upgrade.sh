#!/bin/bash

### 3 params: json, key, defaultValue
function getJsonValuesByAwk() {
    awk -v json="$1" -v key="$2" -v defaultValue="$3" 'BEGIN{
        foundKeyCount = 0
        while (length(json) > 0) {
            # pos = index(json, "\""key"\"");
            pos = match(json, "\""key"\"[ \\t]*?:[ \\t]*");
            if (pos == 0) {if (foundKeyCount == 0) {print defaultValue;} exit 0;}

            ++foundKeyCount;
            start = 0; stop = 0; layer = 0;
            for (i = pos + length(key) + 1; i <= length(json); ++i) {
                lastChar = substr(json, i - 1, 1)
                currChar = substr(json, i, 1)

                if (start <= 0) {
                    if (lastChar == ":") {
                        start = currChar == " " ? i + 1: i;
                        if (currChar == "{" || currChar == "[") {
                            layer = 1;
                        }
                    }
                } else {
                    if (currChar == "{" || currChar == "[") {
                        ++layer;
                    }
                    if (currChar == "}" || currChar == "]") {
                        --layer;
                    }
                    if ((currChar == "," || currChar == "}" || currChar == "]") && layer <= 0) {
                        stop = currChar == "," ? i : i + 1 + layer;
                        break;
                    }
                }
            }

            if (start <= 0 || stop <= 0 || start > length(json) || stop > length(json) || start >= stop) {
                if (foundKeyCount == 0) {print defaultValue;} exit 0;
            } else {
                print substr(json, start, stop - start);
            }

            json = substr(json, stop + 1, length(json) - stop)
        }
    }'
}

while true ; do
    case "$1" in
        -c)
            config_file=$2
            if [ -z $2 ]; then
                shift 1
            else
                shift 2
            fi
            ;;
        --) 
            shift ;
            break ;;
        *)
            if [ x"$cmd_run" = x"" ]; then
                cmd_run="help"
            fi
            break;
            ;;
    esac
done

if [ x"$config_file" == x"" ]; then
    echo "please give right config file"
    exit -1
fi

config=`cat $config_file`
chain_config=`getJsonValuesByAwk "$config" "chain" "{}"`
api_base_url=`getJsonValuesByAwk "$chain_config" "base_url" ""`
sworker_base_url=(`getJsonValuesByAwk "$config" "base_url" ""`)

if [ x"${sworker_base_url[0]}" == x"$api_base_url" ]; then
sworker_base_url=${sworker_base_url[1]}
else
sworker_base_url=${sworker_base_url[0]}
fi

if [ x"$api_base_url" == x"" ] || [ x"$sworker_base_url" == x"" ]; then
    echo "please give right config file"
    exit -1
fi

api_base_url=`echo "$api_base_url" | sed -e 's/^"//' -e 's/"$//'`
sworker_base_url=`echo "$sworker_base_url" | sed -e 's/^"//' -e 's/"$//'`

while :
do
system_health=`curl $api_base_url/system/health 2>/dev/null`
if [ x"$system_health" = x"" ]; then
    echo "please run crust chain and api"
    sleep 10
    continue
fi

is_syncing=`getJsonValuesByAwk $system_health "isSyncing" ""`
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

code=`curl $api_base_url/tee/code 2>/dev/null`
if [ x"$code" = x"" ]; then
    echo "please run chain and api"
    sleep 10
    continue
fi
code=`echo ${code: 3: 64}`
echo "sWorker code on chain: $code"

id_info=`curl $sworker_base_url/enclave/id_info 2>/dev/null`
if [ x"$id_info" = x"" ]; then
    echo "please run sworker"
    sleep 10
    continue
fi
id_info=`echo $id_info | sed 's/ //g'`
mrenclave=`getJsonValuesByAwk $id_info "mrenclave" ""`
if [ x"$mrenclave" = x"" ]; then
    echo "waiting sworker ready"
    sleep 10
    continue
fi
mrenclave=`echo ${mrenclave: 1: 64}`

echo "sWorker self code: $mrenclave"

if [ x"$mrenclave" != x"$code" ]; then
    echo "Upgrade..."
fi

sleep 10
done
