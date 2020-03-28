#!/bin/bash

dir="$1"
offset="$2"

find "$1" -type f | ( \
	while read f
       	do
		casename=$(printf "%06x" $offset)
		mkdir -p t_$casename/reference
		cp "$f" t_$casename
		echo 'IMAGE="'$(basename "$f")'"' > t_$casename/test.sh
		offset=$((offset+1))
	done )
