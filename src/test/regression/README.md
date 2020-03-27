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


