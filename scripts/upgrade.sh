function compare_version()
{
    ### v1  > v2 return 1
    ### v1  < v2 return -1
    ### v1 == v2 return 0
    local v1=($(echo $1 | sed "s/\./ /g"))
    local v2=($(echo $2 | sed "s/\./ /g"))
    local ans=0

    for i in ${!v1[@]}; do
        if [ $i -ge ${#v2[@]} ] || [ ${v1[$i]} -gt ${v2[$i]} ]; then
            ans=1
            break
        fi
        if [ ${v1[$i]} -lt ${v2[$i]} ]; then
            ans=-1
            break
        fi
    done
    if [ $ans -eq 0 ]; then
        if [ ${#v1[@]} -lt ${#v2[@]} ]; then
            ans=-1
        fi
    fi

    echo $ans
}

############## MAIN BODY ###############
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)
crustdir=$(cd $instdir/..;pwd)

. $basedir/utils.sh

cd $instdir
if [ ! -e "crust-tee.tar" ]; then
    verbose ERROR "Upgrade failed!Please put crust-tee.tar to this directory!"
    exit 1
else
    tar -xvf crust-tee.tar &>/dev/null
    cur_version=$(cat VERSION)
    new_version=$(cat crust-tee/VERSION)
    if [ $(compare_version $new_version $cur_version) -le 0 ]; then
        verbose ERROR "Upgrade failed!New version not newer than current version!"
        rm -rf crust-tee
        exit 1
    fi
    upgrade_dir=crust-tee_$(cat crust-tee/VERSION)
    mv crust-tee $upgrade_dir
    mv $upgrade_dir $crustdir
    verbose INFO "Upgrade successfully!"
fi
cd - &>/dev/null
