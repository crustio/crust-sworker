#! /usr/bin/env bash
# build crust runner docker image

usage() {
    echo "Usage:"
		echo "    $0 -h                      Display this help message."
		echo "    $0 [options]"
    echo "Options:"
    echo "     -p publish image"

	  exit 1;
}

PUBLISH=0

while getopts ":hp" opt; do
    case ${opt} in
        h )
			      usage
            ;;
        p )
            PUBLISH=1
            ;;
        \? )
            echo "Invalid Option: -$OPTARG" 1>&2
            exit 1
            ;;
    esac
done


echo "building crust runner image"

if [ "$PUBLISH" -eq "1" ]; then
    echo "will publish after build"
fi

DIST_FILE="crust-tee.tar"
VER=`cat VERSION`
IMAGEID="crustio/tee-runner:$VER"

if [ ! -f "$DIST_FILE" ]; then
    echo "$DIST_FILE doesn't exsit!"
    exit 1
fi

cp $DIST_FILE docker/tee-runner/

docker build docker/tee-runner -t $IMAGEID

if [ "$?" -ne "0" ]; then
    echo "tee-runner build failed!"
    exit 1
fi

echo "tee-runner build success"
if [ "$PUBLISH" -eq "1" ]; then
    echo "will publish image to $IMAGEID"
    docker push $IMAGEID
fi

