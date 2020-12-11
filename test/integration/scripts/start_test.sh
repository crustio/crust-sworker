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
    # Kill sworker process
    local spid=$(cat $sworkerpidfile)
    kill -9 $spid &>/dev/null
    wait $spid &>/dev/null

    ### Clean test data
    if [ x"$datadir" != x"" ]; then
        rm -rf $datadir &>/dev/null
    fi

    ### Clean err file
    if [ ! -s "$errfile" ]; then
        rm $errfile &>/dev/null
    fi

    ### Clean tmp dir
    if [ x"$roottmpdir" != x"" ]; then
        rm -rf $roottmpdir &>/dev/null
    fi

    ### Clean functionality tmp dir
    if [ x"$functionalitytmpdir" != x"" ]; then
        rm -rf $functionalitytmpdir &>/dev/null
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
    killed=true
    success_exit

    # Kill descendent processes
    print_end
    if [ x"$parent_sworkerpid" != x"" ] && [[ $parent_sworkerpid =~ ^[1-9][0-9]*$ ]]; then
        kill_descendent $parent_sworkerpid
    else
        kill_descendent $cursworkerpid
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
functionalitycasedir=$instdir/functionality
functionalitytmpdir=$instdir/functionality/tmp
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
roottmpdir=$instdir/tmp
sworkerpidfile=$roottmpdir/sworkerpid
reportheightfile=$roottmpdir/report_file
configfile=$instdir/config/config.json
crustdir=/opt/crust
ipfsdatadir=$crustdir/data/ipfs
ERA_LENGTH=300
REPORT_WAIT_BM=15
cursworkerpid=$$
pad="$(printf '%0.1s' ' '{1..10})"
casedir=""
killed=false
IPFS_HELPER=$scriptdir/ipfs_helper
GEN_RANDOM_DATA=$scriptdir/gen_random.sh

trap "success_exit" EXIT
trap "kill_process" INT

. $basedir/utils.sh

mkdir -p $datadir
mkdir -p $testfiledir
mkdir -p $roottmpdir

export baseurl
export benchmarkfile
export sworkerpidfile
export reportheightfile
export configfile
export ipfsdatadir
export ERA_LENGTH
export REPORT_WAIT_BM
export IPFS_HELPER
export GEN_RANDOM_DATA


printf "%s%s\n"   "$pad" '                             __                __            __ '
printf "%s%s\n"   "$pad" '   ______      ______  _____/ /_____  _____   / /____  _____/ /_'
printf "%s%s\n"   "$pad" '  / ___/ | /| / / __ \/ ___/ //_/ _ \/ ___/  / __/ _ \/ ___/ __/'
printf "%s%s\n"   "$pad" ' (__  )| |/ |/ / /_/ / /  / ,< /  __/ /     / /_/  __(__  ) /_  '
printf "%s%s\n\n" "$pad" '/____/ |__/|__/\____/_/  /_/|_|\___/_/      \__/\___/____/\__/  '


while getopts "t:p:c:" opt &>/dev/null; do
    case $opt in
        t)  run_type=$OPTARG;;
        p)  parent_sworkerpid=$OPTARG;;
        c)  case_arry=$OPTARG;;
        *)  ;;
    esac
done

if [ x"$run_type" = x"functionality" ]; then
    casedir=$functionalitycasedir
elif [ x"$run_type" = x"benchmark" ]; then
    casedir=$benchmarktestdir
elif [ x"$run_type" = x"performance" ]; then
    casedir=$performancetestdir
else
    usage
    exit 1
fi

### Select chose cases
orgcase_arry=($(ls $casedir | sort))
if [ x"$case_arry" != x"" ]; then
    declare -A cname2idx
    declare -A cidx2name
    for el in ${orgcase_arry[@]}; do
        name=${el#*_}
        idx=${el%_*}
        cname2idx[$name]=$idx
        cidx2name[$idx]=$name
    done
    usecase_arry=()
    index=0
    for el in $(echo $case_arry | sed -e 's/\[\|\]//g' -e 's/,/\n/g'); do
        if [[ $el =~ ^[0-9]+$ ]]; then
            case_name=${el}_${cidx2name[$el]}
        else
            if [ x"${cname2idx[$el]}" = x"$el" ]; then
                case_name=$el
            else
                case_name=${cname2idx[$el]}_${el}
            fi
        fi
        if ls $casedir | grep $case_name &>/dev/null; then
            usecase_arry[$index]=$case_name
            ((index++))
        fi
    done
else
    usecase_arry=(${orgcase_arry[@]})
fi

if [ ${#usecase_arry[@]} -eq 0 ]; then
    verbose WARN "No test case seleted!"
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
sleep 10
while true; do
    curl -s $baseurl/workload 2>$errfile 1>$TMPFILE
    if [ $? -ne 0 ] ; then
        verbose ERROR "failed" t
        verbose ERROR "start crust sworker failed! Please check $errfile for details."
        kill -9 $sworkerpid
        exit 1
    elif cat $TMPFILE | jq '.' &>/dev/null; then
        break
    fi
    sleep 1
done
if ! ps -ef | grep -v grep | grep $sworkerpid &>/dev/null; then
    verbose ERROR "failed" t
    exit 1
fi
verbose INFO "success" t
echo $sworkerpid > $sworkerpidfile
cd - &>/dev/null

# Generate ipfs_helper
cd $basedir
go get
go build ipfs_helper.go
cd - &>/dev/null

# Generate test srd file
$scriptdir/gen_random.sh 1m $datadir/srd_test

### Run test cases
cd $casedir
verbose INFO "starting $run_type cases:" n
true > $caseresfile
disown -r
cur_index=1
success_num=0
failed_num=0
for script in ${usecase_arry[@]}; do
    if [ ! -f $script ]; then
        continue
    fi
    true > $SYNCFILE
    show_name=${script#*_}
    setTimeWait "$(verbose INFO "running test case($cur_index/${#usecase_arry[@]}): $show_name..." h)" $SYNCFILE &
    print_title "start $show_name case" &>> $caseresfile
    bash $script &>> $caseresfile
    ret=$?
    checkRes $ret "return" "success" "$SYNCFILE"
    if [ $ret -eq 0 ]; then
        ((success_num++))
    else
        ((failed_num++))
    fi
    ((cur_index++))
done
cd - &>/dev/null
verbose INFO "total: $((success_num+failed_num)), success: ${HGREEN}$success_num${NC}, failed: ${HRED}$failed_num${NC}" n
