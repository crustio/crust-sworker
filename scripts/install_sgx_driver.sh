#!/bin/bash
scriptdir=$(cd `dirname $0`;pwd)
basedir=$(cd $scriptdir/..;pwd)

is_16=`cat /etc/issue | grep 16.04`
if [ x"$is_16" = x"" ]; then
    driverbin=sgx_linux_x64_driver_2.6.0_4f5bb63.bin
    driverurl=https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu18.04-server/$driverbin
else
    driverbin=sgx_linux_x64_driver_2.6.0_4f5bb63.bin
    driverurl=https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu16.04-server/$driverbin
fi

. $scriptdir/utils.sh

log_info "Apt-get update..."
apt-get update 

log_info "Installing denpendencies..."
apt-get install -y wget build-essential kmod linux-headers-`uname -r`

log_info "Download sgx driver"
wget $driverurl

log_info "Give sgx driver executable permission"
chmod +x $driverbin

log_info "Installing sgx driver..."
./$driverbin

log_info "Clear resource"
rm $driverbin
