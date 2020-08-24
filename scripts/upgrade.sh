#!/bin/bash
scriptdir=$(cd `dirname $0`;pwd)
basedir=$(cd $scriptdir/..;pwd)

while :
do
code=`curl ${$1}/api/v1/tee/code`
echo $code
sleep 10
done
