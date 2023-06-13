#!/bin/bash

# set_reference_from_case.sh case1 case2 ...

for c in "$@"
do
	cp $c/unpack/*/bang.pickle $c/reference
done
