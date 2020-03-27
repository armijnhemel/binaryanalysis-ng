#!/bin/sh

# docker end to end test

# map image directory to firmware data directory
IMAGE_DIR=$(dirname "$1")
IMAGE=$(basename "$1")
UNPACK_DIR=$HOME/bang-unpack
TMP_DIR=$HOME/bang-tmp

userid=$(id -u)
groupid=$(id -g)

docker container run --rm -it \
 	-u $userid:$groupid \
	-v "$IMAGE_DIR":/data \
	-v "$UNPACK_DIR":/bang-unpack \
	-v "$TMP_DIR":/bang-tmp \
	bang python3 /usr/src/bang/src/bang-scanner \
	-c /usr/src/bang/src/bang.config \
	-u /bang-unpack \
	-t /bang-tmp \
	-f /data/$IMAGE

