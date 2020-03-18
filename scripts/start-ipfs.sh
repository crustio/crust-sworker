#!/bin/bash

crust_tee_main_install_dir=/opt/crust/crust-tee
ipfs_data_path=$HOME/.ipfs
ipfs_bin=$crust_tee_main_install_dir/bin/ipfs

. $crust_tee_main_install_dir/stcript/utils.sh

if [ -d "$ipfs_data_path" ]; then
    verbose INFO "IPFS has been initialized." n
else
    verbose INFO "Set swarm key ..." h
    mkdir -p $ipfs_data_path
    cp $swarm_key $ipfs_data_path
    checkRes $? "return"

    verbose INFO "Init ipfs..." h
    $ipfs_bin init
    checkRes $? "return"

    verbose INFO "Remove public bootstrap..." h
    $ipfs_bin bootstrap rm --all &>/dev/null
    checkRes $? "return"

    verbose INFO "Set swarm address ..." h
    $ipfs_bin config Addresses.Swarm --json "[\"/ip4/0.0.0.0/tcp/14001\", \"/ip6/::/tcp/14001\"]" &>/dev/null
    checkRes $? "return"
    
    verbose INFO "Set api address ..." h
    $ipfs_bin config Addresses.API /ip4/0.0.0.0/tcp/15001 &>/dev/null
    checkRes $? "return"

    verbose INFO "Set gateway address ..." h
    $ipfs_bin config Addresses.Gateway /ip4/127.0.0.1/tcp/18080 &>/dev/null
    checkRes $? "return"
    
    verbose INFO "Remove all useless data ..." h
    $ipfs_bin pin rm $($ipfs_bin pin ls -q --type recursive) &>/dev/null
    $ipfs_bin repo gc &>/dev/null
    checkRes $? "return"
fi

$ipfs_bin daemon
