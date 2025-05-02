# Regression tests

This script runs bang-scanner on a set of test cases and compares the result
to a reference value. The script requires a docker container installation of
bang.

Every test case has the following layout:


```
t_00000
   +------ test.sh
   +------ reference
   |          +------- bang.pickle
   +------ openwrt-wrt54g-squashfs.bin
```

The file `test.sh` points to the firmware image to be tested, in this case
`openwrt-wrt54g-squashfs.bin`:

```
IMAGE=openwrt-wrt54g-squashfs.bin
```

You can run the script on all test cases:

```
/path/to/bang/src/test/regression/run.sh t_00000 t_00001 > test.log
```

On the first run of a test case, there is no `bang.pickle` reference file. After the scan,
you will need to copy the scan result to the `reference` directory, like this:

```
cd t_00000
cp unpack/bang-scan-v3ki58p3/bang.pickle reference
```

# Creating test cases for a collection of binaries

If you have a directory with binaries only, you can create test cases automatically
with a few auxilliary scripts.

`make_testcases.sh` traverses a directory and creates test cases in the current directory
for every regular file it finds. Example:

```
make_testcases.sh /my/collection/of/firmware  # starts numbering at 0
make_testcases.sh /other/collection 7         # starts numbering at 7
```

# Comparing two builds

If you want to compare two builds against a collection of firmware images, first create a
new collection without any reference files.

Then, copy the `src/test/regression/run.sh` script to `run_first.sh`, and change the line:

```
	bang python3 /usr/src/bang/src/bang-scanner \
```

to

```
	bangfirst python3 /usr/src/bang/src/bang-scanner \
```

Now, check out the first version, for example:

```
git checkout 9637bb9e49361c541c2a9c278876aee2f5ab7c9d
```

Make a docker image named `bangfirst`, or whatever name you chose earlier:

```
docker image build -t bangfirst .
```

Then, check out the second version, and build the docker image named `bang`, if you have not
done this already, for example:

```
git checkout master
docker image build -t bang .
```

In the directory of test cases, run the script `run_first.sh`:

```
run_first.sh t_*
```

Once this is done, create the reference files:

```
/path/to/bang/src/test/regression/set_reference_from_case.sh t_*
```

Now you can run the regular `run.sh` to compare the output against the first output.

**Note:** sometimes the run can hang if there is an uncaught exception. In this case,
send an interrupt with control-c, and the run should continue.


