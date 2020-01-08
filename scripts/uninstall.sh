#!/bin/bash
basedir=$(cd `dirname $0`;pwd)
instdir=$(cd $basedir/..;pwd)

$instdir/scripts/stop.sh
rm -rf $instdir/*

echo "Uninstall crust successfully!"
