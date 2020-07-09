#! /usr/bin/env bash

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

/opt/crust/crust-tee/bin/crust-tee
