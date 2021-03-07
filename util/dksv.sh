#!/bin/sh

CTR_RUN=podman
CTR_KSV=ksv

if [ $# -ne 2 ]
then
	echo "Usage: dksv.sh image_file format_file"
	exit 1
fi

IMAGE=$(realpath "$1")
FORMAT=$(realpath "$2")

$CTR_RUN container run -u $(id -u):$(id -g) -v "$IMAGE":/image:z -v "$FORMAT":/format.ksy:z -it --rm "$CTR_KSV" ksv /image /format.ksy

