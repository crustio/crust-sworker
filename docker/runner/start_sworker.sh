#! /usr/bin/env bash

crustdir=/opt/crust
version=$(cat /crust-sworker/VERSION | head -n 1)
crustsworkerdir=$crustdir/crust-sworker/$version
crust_env_file=$crustsworkerdir/etc/environment
inteldir=/opt/intel
echo "Run sworker with arguments: $ARGS"
source $crust_env_file
/opt/crust/crust-sworker/$version/bin/crust-sworker $ARGS
