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
    echo "Aesm service running"
else
    echo "Aesm service not running, starting it"
    $inteldir/libsgx-enclave-common/aesm/aesm_service &
    echo "Wait 5 seconds for aesm service fully start"
    sleep 5
fi

echo "Run tee with arguments: $ARGS"
/opt/crust/crust-tee/$version/bin/crust-tee $ARGS

