#!/bin/sh

SCRIPT_DIR=$(realpath $(dirname "$0"))
TESTDATA_DIR=test/testdata/download

echo $SCRIPT_DIR

dlcurl ()
{
	url=$1
	fn=$2
	mkdir -p $SCRIPT_DIR/../src/$TESTDATA_DIR/$(dirname "$fn") && \
	curl $url -o $SCRIPT_DIR/../src/$TESTDATA_DIR/"$fn"
}

dlcurl_gunzip ()
{
	dlcurl $1 "$2.gz"
	gunzip $SCRIPT_DIR/../src/$TESTDATA_DIR/"$2".gz
}

dlcurl_bunzip ()
{
	dlcurl $1 "$2.bz2"
	bunzip2 $SCRIPT_DIR/../src/$TESTDATA_DIR/"$2".bz2
}


while read -a fileinfo
do
	processor=${fileinfo[0]}
	url=${fileinfo[1]}
	fn=${fileinfo[2]}

	echo "--> Checking $fn..." &&
	[ -f $SCRIPT_DIR/../src/$TESTDATA_DIR/"$fn"  ] || $processor $url "$fn"
done

