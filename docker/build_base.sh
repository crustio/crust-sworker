#! /usr/bin/env bash
# script to build tee build base image

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

VER=`cat VERSION`
echo "building docker base image, version: $VER"
if [ "$PUBLISH" -eq "1" ]; then
  echo "will publish after build"
fi

#mkdir -p .tmp
#tar -xf vendor/files.tar -C .tmp files/resource
#mv .tmp/files/resource/* docker/tee-build/
#cp vendor/onetbb.tar docker/tee-build/

IMAGEID="crustio/tee-build:$VER"
docker build docker/tee-build -t $IMAGEID

if [ "$?" -ne "0" ]; then
  echo "build failed!"
  exit 1
fi

echo "build success"
if [ "$PUBLISH" -eq "1" ]; then
  echo "will publish image to $IMAGEID"
  docker push $IMAGEID
fi

