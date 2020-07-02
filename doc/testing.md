# Testing BANG

Testing BANG is important to find regressions. Currently there are three kinds of tests:

1. unit tests for individual files. These tests can be found inside the BANG repository. The test files are found in the directory 'src/test/testdata'. The script to test these is 'src/test/TestUnpackers.py'.
2. regression tests with a large collection of firmware files. This is run regularly (every few weeks) to find any crashes or other odd behaviour. The firmware collection cannot be redistributed freely, so has not been made available.
3. profiling to see which functions are called the most

## Unit tests

All test code is available as a Python module from the `src` directory, for example:

```
python3 -m unittest test.TestFileResult.TestFileResult.test_fileresult_has_correct_filenames
```

This is the preferred and recommended way of running unit tests.
You can find unit tests for unpack parsers in the file `Test.py` of the corresponding parser. For example:

```
python3 -m unittest -v parsers.image.gif.Test.TestGifUnpackParser.test_extracted_gif_file_is_correct
```

The `-v` flag will make testing more verbose.
To run all tests, we use the `discover` command from the `unittest` module:

```
python3 -m unittest discover -v -p 'Test*'
```

This looks for test classes in all files starting with `Test` and runs their tests.

You can see test coverage by running the test with Python's coverage module, for which you will need to install `coverage` first:

```
pip3 install coverage
```

Then run:

```
coverage3 run -m unittest test.TestFileResult.TestFileResult.test_fileresult_has_correct_filenames
coverage3 html -d test/coverage
```

The file `test/coverage/index.html` will give you the coverage report.

The `Makefile` under `src` contains the following targets:

test: runs all tests,

parsertests: runs tests for all parsers,

coverage: runs all test and writes coverage report in `test/coverage`.

## Notes

Some several notes which can be useful.

### Batch mode

To scan large amounts of files it is best to use the '-d' flag to BANG to scan lots of files, and to set "removescandirectory" in the configuration file to "yes".

### Profiling

See https://docs.python.org/3/library/profile.html for background. Run BANG under a profiler as follows:

    $ python3 -mprofile -s "time" bang-scanner -c bang.config -f /path/to/firmware

Word of warning: profiling could have a very big performance impact.

### ext2

For ext2 a good set of testing data can be found in the e2fsprogs Git repository:

https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/tree/tests

### PNG/JPEG/GIF

Wikipedia's dumps in ZIM format possibly contain lots of pictures made with many different programs.
