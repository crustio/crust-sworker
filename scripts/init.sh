#!/bin/sh

ipfsp=$HOME"/.ipfs/"

if [ ! -d "$ipfsp" ]; then
    echo "Give ipfs executable permission ...."
    sudo chmod +x ipfs

    echo "Init ipfs ..."
    ./ipfs init

    echo "Set swarm key ..."
    cp swarm.key "$ipfsp"

    echo "Remove public bootstrap ..."
    ./ipfs bootstrap rm --all

    if [ -z $MASTER_ADDRESS ]; then
        echo "This node is master node ..."
    else
        echo "This node is slave, master node is '[$MASTER_ADDRESS]'' ..."
        ./ipfs bootstrap add $MASTER_ADDRESS
    fi

    sudo ufw allow 22
    sudo ufw allow 5001
    sudo ufw allow 4001
    sudo ufw enable
    sudo ufw reload

    echo "Set swarm address ..."
    IPFS_SWARM_ADDR_IPV4=\"/ip4/0.0.0.0/tcp/4001\"
    IPFS_SWARM_ADDR_IPV6=\"/ip6/::/tcp/4001\"
    ./ipfs config Addresses.Swarm --json "[$IPFS_SWARM_ADDR_IPV4, $IPFS_SWARM_ADDR_IPV6]"

    echo "Set api address ..."
    ./ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001

    echo "Remove all data ..."
    ./ipfs pin rm $(./ipfs pin ls -q --type recursive)
    ./ipfs repo gc
else
    echo "IPFS has been initialized ... "
fi
