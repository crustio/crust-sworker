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

VER=$(cat VERSION | head -n 1)
IMAGEID="crustio/crust-tee-env:$VER"
echo "building $IMAGEID image"
if [ "$PUBLISH" -eq "1" ]; then
  echo "will publish after build"
fi


docker build -f docker/env/Dockerfile -t $IMAGEID .

if [ "$?" -ne "0" ]; then
  echo "crust-tee-env build failed!"
  exit 1
fi

echo "build success"
if [ "$PUBLISH" -eq "1" ]; then
  echo "will publish $IMAGEID image"
  docker push $IMAGEID
fi
