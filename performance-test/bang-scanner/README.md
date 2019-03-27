# Performance test scripts for bang-scanner

## Running the tests

Make sure there is enough disk space to unpack the whole archive and some more.
Then, go to the directory where you want the test results to be stored and call
the run-tests.sh script

```
bash /path/to/run-tests.sh <testid> <iterations> <scanfile>
```

e.g.

```
bash run-tests 0001 30 ~/testdata/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz
```

After the tests are done, there will be a directory `perftest-0001` that contains a file `timings.json.csv`. It will look something like this:

```
testid,run,real,user,system,duration
0001,0,2.084,1.77,0.302,1.91403
0001,1,2.049,1.729,0.31,1.89979
0001,2,2.064,1.701,0.35,1.916161
```

## Comparing two tests

You can combine multiple test timings into one CSV file, by calling `combine-perftests.py`:

```
python3 combine-perftests.py <testdir1> <testdir2> ...
```

You can then load the results in a spreadsheet or program to run statistical analysis on.


