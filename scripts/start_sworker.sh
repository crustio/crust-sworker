#! /usr/bin/env bash

# This script is used to start sworker locally for testing purpose
basedir=$(cd `dirname $0`;pwd)

. $basedir/utils.sh

crustdir=/opt/crust
version=$(getVERSION)
crustsworkerdir=$crustdir/crust-sworker/$version
crust_env_file=$crustsworkerdir/etc/environment

echo "Starting crust sworker $version"
source $crust_env_file

wait_time=10
echo "Wait $wait_time seconds for aesm service fully start"
/opt/intel/sgx-aesm-service/aesm/linksgx.sh
/bin/mkdir -p /var/run/aesmd/
/bin/chown -R aesmd:aesmd /var/run/aesmd/
/bin/chmod 0755 /var/run/aesmd/
/bin/chown -R aesmd:aesmd /var/opt/aesmd/
/bin/chmod 0750 /var/opt/aesmd/
NAME=aesm_service AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service
sleep $wait_time

ps -ef | grep aesm

SGXTYPE=""
for el in $(cpuid | grep -i "SGX launch config" | awk '{print $NF}'); do
    SGXTYPE="--ecdsa"
    if [ x"$el" != x"true" ]; then
        SGXTYPE=""
        break
    fi
done

/opt/crust/crust-sworker/$version/bin/crust-sworker -c /opt/crust/crust-sworker/$version/etc/Config.json $SGXTYPE --debug
