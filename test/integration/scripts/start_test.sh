#!/bin/bash
function usage()
{
cat << EOF
    start_test [option] [args]:
        -t: run type:functionality, benchmark or performance
        -c: case name
        -p: parent pid
EOF
}

function success_exit()
{
    local cur_sworkerpid=$(ps -ef | grep -v grep | grep "\b${sworkerpid}\b" | awk '{print $2}')
    if [ x"$cur_sworkerpid" = x"$sworkerpid" ]; then
        kill -9 $sworkerpid &>/dev/null
        wait $sworkerpid &>/dev/null
    fi

    ### Clean test data
    if [ x"$datadir" != x"" ]; then
        rm -rf $datadir &>/dev/null
    fi

    ### Clean err file
    if [ ! -s "$errfile" ]; then
        rm $errfile &>/dev/null
    fi

    rm $SYNCFILE &>/dev/null
    rm $TMPFILE &>/dev/null
    rm $TMPFILE2 &>/dev/null

    if [ x"$killed" = x"false" ]; then
        print_end
    fi
}

function kill_process()
{
    # Kill descendent processes
    print_end
    killed=true
    if [ x"$parent_sworkerpid" != x"" ] && [[ $parent_sworkerpid =~ ^[1-9][0-9]*$ ]]; then
        kill -- -$parent_sworkerpid
    else
        kill -- -$cursworkerpid
    fi
}

function print_end()
{
    printf "%s%s\n"   "$pad" '                                         '
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
functionalitytestdir=$instdir/functionality
benchmarktestdir=$instdir/benchmark
performancetestdir=$instdir/performance
testdir=$instdir/test_app
errfile=$basedir/err.log
caseresfile=$instdir/case.log
testfiledir=$testdir/files
sworkerlog=$instdir/sworker.log
benchmarkfile=$instdir/benchmark.report_$(date +%Y%m%d%H%M%S)
testconfigfile=$testdir/etc/Config.json
baseurl=$(cat $testconfigfile | jq ".base_url" | sed 's/"//g')
SYNCFILE=$basedir/SYNCFILE
TMPFILE=$instdir/TMPFILE
TMPFILE2=$instdir/TMPFILE2
cursworkerpid=$$
pad="$(printf '%0.1s' ' '{1..10})"
casedir=""
killed=false

trap "success_exit" EXIT
trap "kill_process" INT

. $basedir/utils.sh

mkdir -p $datadir
mkdir -p $testfiledir

export baseurl
export benchmarkfile


printf "%s%s\n"   "$pad" '                             __                __            __ '
printf "%s%s\n"   "$pad" '   ______      ______  _____/ /_____  _____   / /____  _____/ /_'
printf "%s%s\n"   "$pad" '  / ___/ | /| / / __ \/ ___/ //_/ _ \/ ___/  / __/ _ \/ ___/ __/'
printf "%s%s\n"   "$pad" ' (__  )| |/ |/ / /_/ / /  / ,< /  __/ /     / /_/  __(__  ) /_  '
printf "%s%s\n\n" "$pad" '/____/ |__/|__/\____/_/  /_/|_|\___/_/      \__/\___/____/\__/  '


while getopts "t:p:c:" opt &>/dev/null; do
    case $opt in
        t)  run_type=$OPTARG;;
        p)  parent_sworkerpid=$OPTARG;;
        c)  case_name=$OPTARG;;
        *)  ;;
    esac
done

if [ x"$run_type" = x"functionality" ]; then
    casedir=$functionalitytestdir
elif [ x"$run_type" = x"benchmark" ]; then
    casedir=$benchmarktestdir
    verbose INFO "starting $run_type cases:" n >> $benchmarkfile
elif [ x"$run_type" = x"performance" ]; then
    casedir=$performancetestdir
else
    usage
    exit 1
fi

if ! ls $casedir | grep "\b${case_name}\b" &>/dev/null; then
    verbose ERROR "no $case_name case!"
    exit 1
fi


### Start crust-sworker
cd $testdir
rm -rf sworker_base_path
rm -rf files
mkdir files
verbose INFO "starting crust-sworker..." h
./bin/crust-sworker -c etc/Config.json --offline --debug &>$sworkerlog &
sworkerpid=$!
sleep 8
curl -s $baseurl/workload 2>$errfile 1>/dev/null
if [ $? -ne 0 ] ; then
    verbose ERROR "failed" t
    verbose ERROR "start crust sworker failed! Please check $errfile for details."
    kill -9 $sworkerpid
    exit 1
fi
if ! ps -ef | grep -v grep | grep $sworkerpid &>/dev/null; then
    verbose ERROR "failed" t
    exit 1
fi
verbose INFO "success" t
cd - &>/dev/null
export sworkerpid

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
verbose INFO "starting $run_type cases:" n
true > $caseresfile
testcase_arry=($(ls | grep -v "restart"))
testcase_arry[${#testcase_arry[@]}]="restart"
disown -r
for script in ${testcase_arry[@]}; do
    if [ x"$case_name" != x"" ] && [ x"$case_name" != x"$script" ]; then
        continue
    fi
    true > $SYNCFILE
    setTimeWait "$(verbose INFO "running test case: $script..." h)" $SYNCFILE &
    bash $script $sworkerpid &>> $caseresfile
    checkRes $? "return" "success" "$SYNCFILE"
done
cd - &>/dev/null
