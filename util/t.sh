#!/bin/sh

if [ -z "$*" ]
then
	docker container run -it --rm -v "$(pwd)":/src:z -w /src bang bash
else
	docker container run -it --rm -v "$(pwd)":/src:z -w /src bang "$@"
fi

