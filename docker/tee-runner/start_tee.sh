#! /usr/bin/env bash

echo "starting tee"

if [ ! -f /opt/crust-installed ]; then
    echo 'install tee dependencies...'
    /opt/crust-bin/crust-tee/install.sh
    if [ $? -eq 0 ]; then
        echo 'dependencies installed'
        touch /opt/crust-installed
    else
        echo 'dependencies install failed!'
        exit 1
    fi
fi

crustdir=/opt/crust
crustteedir=$crustdir/crust-tee
crust_env_file=$crustteedir/etc/environment
inteldir=/opt/intel

source $crust_env_file
export LD_LIBRARY_PATH=LD_LIBRARY_PATH:$inteldir/libsgx-enclave-common/aesm

#
# ensure aesm service is running
# otherwise enclave will not be initialized
if pgrep -x "aesm_service" > /dev/null
then
    echo "aesm service running"
else
    echo "aesm service not running, starting it"
    $inteldir/libsgx-enclave-common/aesm/aesm_service &
    echo "wait 5 seconds for aesm service fully start"
    sleep 5
fi


APP_ARGS=${TEE_ARGS:-""}

echo "run tee with arguments: $APP_ARGS"

/opt/crust/crust-tee/bin/crust-tee $APP_ARGS
