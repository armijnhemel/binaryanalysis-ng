#!/bin/sh

userid=$(id -u)
groupid=$(id -g)

run_bangscanner ()
{
	image_dir="$1"
	unpack_dir="$2"
	tmp_dir="$3"
	image="$4"
	docker container run --rm -it \
		-u $userid:$groupid \
		-v "$image_dir":/data \
		-v "$unpack_dir":/bang-unpack \
		-v "$tmp_dir":/bang-tmp \
		bang python3 /usr/src/bang/src/bang-scanner \
		-c /usr/src/bang/src/bang.config \
		-u /bang-unpack \
		-t /bang-tmp \
		-f /data/"$image"
}

run_bangdiff ()
{
	testcase_dir="$1"
	result_file="$2"
	docker container run --rm -it \
		-u $userid:$groupid \
		-v "$testcase_dir":/bang-test \
		bang python3 /usr/src/bang/src/test/cmp_pickle.py \
			/bang-test/unpack/"$result_file" /bang-test/reference/bang.pickle
}

for f in "$@"
do
	echo "==> Running test case $f..."
	source $f/test.sh

	rm -rf "$f/unpack" "$f/tmp"
	mkdir "$f/unpack" "$f/tmp"

	dir=$(realpath "$f")

	run_bangscanner "$dir" "$dir/unpack" "$dir/tmp" "$IMAGE"

	result_file=$(find "$f/unpack" -name bang.pickle -printf '%P')
	echo "--> Comparing $result_file with reference..."
	run_bangdiff "$dir" "$result_file"
done

