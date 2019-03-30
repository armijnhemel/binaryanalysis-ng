#!/bin/bash
#
# Usage:
# 
# run-tests.sh <testid> <iterations> <firmware file>
#
# Creates a directory perftest-<testid> in the current directory, in which the
# firmware is unpacked. Make sure there is enough disk space. After a
# run the results are removed.
#

basedir=`dirname $0`

BANG_SCANNER=$basedir/../../src/bang-scanner
TESTID=$1
shift
ITERATIONS=$1
shift
FW="$1"

PERFTESTDIR=perftest-"$TESTID"
PERFTESTFILE="$PERFTESTDIR"/timings.json

mkdir -p "$PERFTESTDIR"

TIMEFORMAT="\"real\": %3R, \"user\": %5U, \"system\": %5S,"

if ( ls "$PERFTESTDIR"/bang-scan-* 2>&1 > /dev/null )
then
	echo "Error: directory $PERFTESTDIR not empty."
	echo "   Please remove bang-scan-* directories from it."
       	exit 1
fi

echo "[ " >> "$PERFTESTFILE"

i=0
while [[ $i != $ITERATIONS ]]
do
	echo "Run $i..."
	echo -n "{ \"testid\": \"$TESTID\", \"run\": $i," >> "$PERFTESTFILE"
	echo python3 "$BANG_SCANNER" -f "$FW" -u "$PERFTESTDIR" -t "$PERFTESTDIR"
	{ time (python3 "$BANG_SCANNER" -f "$FW" -u "$PERFTESTDIR" -t "$PERFTESTDIR") ; } 2>> "$PERFTESTFILE"
	echo "done! Recording timings..."
	echo -n '"duration": ' >> "$PERFTESTFILE"
	python3 -c "import sys,pickle; print(pickle.load(open(sys.argv[1],'rb'))['session']['duration'])" "$PERFTESTDIR"/bang-scan-*/bang.pickle >> "$PERFTESTFILE"
	echo "Cleaning up..."
	echo rm -rf "$PERFTESTDIR"/bang-scan-*
	rm -rf "$PERFTESTDIR"/bang-scan-*
	((i++))
	if [[ $i != $ITERATIONS ]]
	then
		echo "}, "  >> "$PERFTESTFILE"
	else
		echo "}"  >> "$PERFTESTFILE"
	fi
done

echo "]" >> "$PERFTESTFILE"

cat $PERFTESTFILE | \
python -c "import sys,json,csv; \
l = json.load(sys.stdin); \
w = csv.DictWriter(sys.stdout, \
fieldnames=['testid','run','real','user','system','duration']); \
w.writeheader(); \
w.writerows(l)" > "$PERFTESTFILE".csv

rm "$PERFTESTFILE"

