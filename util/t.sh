#!/bin/sh

TEST_TMP_DIR=$(pwd)/tmp/bangtest

rm -rf $TEST_TMP_DIR/*
mkdir -p $TEST_TMP_DIR


if [ -z "$*" ]
then
	docker container run -it --rm -u $(id -u):$(id -g) -v "$(pwd)":/src:z -v "$TEST_TMP_DIR":/bangtmp:z -w /src bang bash
else
	docker container run -it --rm -u $(id -u):$(id -g) -v "$(pwd)":/src:z -v "$TEST_TMP_DIR":/bangtmp:z -w /src bang "$@"
fi

