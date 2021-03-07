#!/bin/sh

CTR_RUN=podman
# CTR_OPTIONS=-u $(id -u):$(id -g) 
CTR_OPTIONS=
TEST_TMP_DIR=$(pwd)/tmp/bangtest

rm -rf $TEST_TMP_DIR/*
mkdir -p $TEST_TMP_DIR


if [ -z "$*" ]
then
	$CTR_RUN container run -it --rm $CTR_OPTIONS -v "$(pwd)":/src:z -v "$TEST_TMP_DIR":/bangtmp:z -w /src bang bash
else
	$CTR_RUN container run -it --rm $CTR_OPTIONS -v "$(pwd)":/src:z -v "$TEST_TMP_DIR":/bangtmp:z -w /src bang "$@"
fi

