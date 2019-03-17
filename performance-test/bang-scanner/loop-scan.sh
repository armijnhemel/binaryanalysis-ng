#!/bin/bash
#
# Usage: loop-scan <iterations> <firmware file>
#

basedir=`dirname $0`

BANG_SCANNER=$basedir/../../src/bang-scanner
ITERATIONS=$1
shift
FW="$1"

i=0
# while [ $i -lt $ITERATIONS ]
while [[ $i != $ITERATIONS ]]
do
	python3 $BANG_SCANNER -c $basedir/bang.config -f "$FW" > /dev/null
	((i++))
done

