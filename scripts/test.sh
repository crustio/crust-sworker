#!/bin/bash

function mytest()
{
    local i=5
    while [ $i -gt 0 ]; do
        echo "tset test "
        sleep 1
        ((i--))
    done
}


echo $$
arry=()
for el in ${arry[@]}; do
    echo hahahhah
done

mytest &
echo "child pid:$!"
