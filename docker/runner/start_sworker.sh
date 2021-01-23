#! /usr/bin/env bash

crustdir=/opt/crust
version=$(cat /crust-sworker/VERSION | head -n 1)
crustsworkerdir=$crustdir/crust-sworker/$version
crust_env_file=$crustsworkerdir/etc/environment
inteldir=/opt/intel

echo "Starting curst sworker $version"
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

echo "Run sworker with arguments: $ARGS"
/opt/crust/crust-sworker/$version/bin/crust-sworker $ARGS
