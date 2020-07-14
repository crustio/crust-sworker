#! /usr/bin/env bash

crustdir=/opt/crust
version=$(cat /crust-tee/VERSION | head -n 1)
crustteedir=$crustdir/crust-tee/$version
crust_env_file=$crustteedir/etc/environment
inteldir=/opt/intel

echo "Starting curst tee $version"
source $crust_env_file
export LD_LIBRARY_PATH=LD_LIBRARY_PATH:$inteldir/libsgx-enclave-common/aesm

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

echo "Run tee with arguments: $APP_ARGS"
/opt/crust/crust-tee//bin/crust-tee $APP_ARGS
