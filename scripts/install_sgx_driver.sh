#!/bin/bash
scriptdir=$(cd `dirname $0`;pwd)
basedir=$(cd $scriptdir/..;pwd)

. $scriptdir/utils.sh

verbose INFO "Apt-get update..."
apt-get update 

verbose INFO "Installing denpendencies..."
apt-get install -y build-essential kmod linux-headers-`uname -r`

verbose INFO "Installing sgx driver..."
./$basedir/resource/sgx_linux_x64_driver_2.6.0_4f5bb63.bin

