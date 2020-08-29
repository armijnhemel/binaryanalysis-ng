#!/bin/sh

if [ -z "$*" ]
then
	docker container run -it --rm -u $(id -u):$(id -g) -v "$(pwd)":/src:z -v /tmp:/tmp:z -w /src bang bash
else
	docker container run -it --rm -u $(id -u):$(id -g) -v "$(pwd)":/src:z -v /tmp:/tmp:z -w /src bang "$@"
fi

