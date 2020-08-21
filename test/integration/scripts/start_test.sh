#!/bin/bash
function success_exit()
{
    local cur_pid=$(ps -ef | grep -v grep | grep "\b${pid}\b" | awk '{print $2}')
    if [ x"$cur_pid" = x"$pid" ]; then
        verbose INFO "test end! kill crust-sworker:$pid" n
        kill -9 $pid &>/dev/null
        wait $pid &>/dev/null
    fi

    ### Clean test data
    if [ x"$datadir" != x"" ]; then
        rm -rf $datadir/*
    fi

    ### Clean err file
    if [ ! -s "$errfile" ]; then
        rm $errfile
    fi

    rm $SYNCFILE

    print_end
}

function print_end()
{
    printf "%s%s\n"   "$pad" '   __            __                    __'
    printf "%s%s\n"   "$pad" '  / /____  _____/ /_   ___  ____  ____/ /'
    printf "%s%s\n"   "$pad" ' / __/ _ \/ ___/ __/  / _ \/ __ \/ __  / '
    printf "%s%s\n"   "$pad" '/ /_/  __(__  ) /_   /  __/ / / / /_/ /  '
    printf "%s%s\n\n" "$pad" '\__/\___/____/\__/   \___/_/ /_/\__,_/   '
}

########## MAIN BODY ##########
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
scriptdir=$instdir/scripts
datadir=$instdir/data
casedir=$instdir/cases
testdir=$instdir/test_app
errfile=$basedir/err.log
sworkerlog=$instdir/sworker.log
benchmarkfile=$instdir/benchmark.report_$(date +%Y%m%d%H%M%S)
testconfigfile=$testdir/etc/Config.json
baseurl=$(cat $testconfigfile | jq ".base_url")
baseurl=${baseurl:1:${#baseurl}-2}
SYNCFILE=$basedir/SYNCFILE
pad="$(printf '%0.1s' ' '{1..10})"

trap "success_exit" EXIT

. $basedir/utils.sh

mkdir -p $datadir

export baseurl
export benchmarkfile


printf "%s%s\n"   "$pad" '                             __                __            __ '
printf "%s%s\n"   "$pad" '   ______      ______  _____/ /_____  _____   / /____  _____/ /_'
printf "%s%s\n"   "$pad" '  / ___/ | /| / / __ \/ ___/ //_/ _ \/ ___/  / __/ _ \/ ___/ __/'
printf "%s%s\n"   "$pad" ' (__  )| |/ |/ / /_/ / /  / ,< /  __/ /     / /_/  __(__  ) /_  '
printf "%s%s\n\n" "$pad" '/____/ |__/|__/\____/_/  /_/|_|\___/_/      \__/\___/____/\__/  '


### Start crust-sworker
cd $testdir
rm -rf tee_base_path
rm -rf files/*
verbose INFO "starting crust-sworker..." h
./bin/crust-sworker -c etc/Config.json --offline &>$sworkerlog &
pid=$!
sleep 8
curl -s $baseurl/workload 2>$errfile 1>/dev/null
if [ $? -ne 0 ]; then
    verbose ERROR "failed" t
    verbose ERROR "start crust sworker failed! Please check $errfile for details."
    kill -9 $pid
    exit 1
fi
verbose INFO "success" t
cd - &>/dev/null

### Prepare test data
verbose INFO "creating test data..." h
volunm_arry=(512k 1m 2m 4m 8m 16m 32m 64m)
for v in ${volunm_arry[@]}; do
    $scriptdir/gen_random.sh $v $datadir/$v
done
volunm_arry2=(128m 256m 512m 1024m)
for v in ${volunm_arry2[@]}; do
    cat $datadir/$((${v%[a-z]*}/2))${v##*[0-9]} > $datadir/$v
    cat $datadir/$((${v%[a-z]*}/2))${v##*[0-9]} >> $datadir/$v
done
verbose INFO "success" t

### Run test cases
cd $casedir
verbose INFO "starting benchmark cases:" n >> $benchmarkfile
for script in `ls`; do
    true > $SYNCFILE
    setTimeWait "$(verbose INFO "running test case: $script..." h)" $SYNCFILE &
    bash $script &>/dev/null
    #bash $script
    checkRes $? "return" "success" "$SYNCFILE"
done
cd - &>/dev/null
