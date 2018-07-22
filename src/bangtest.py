#!/usr/bin/python3

## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU Affero General Public License version 3
## SPDX-License-Identifier: AGPL-3.0-only
##
## Test modules for BANG

import unittest
import tempfile
import shutil
import os
import sys
import stat
import pathlib

## load own modules
import bangunpack

basetestdir = '/home/armijn/git/binaryanalysis-ng/test'

class TestGIF(unittest.TestCase):

    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases. There could be warnings like:
    ## ResourceWarning: unclosed file <_io.BufferedReader name='/tmp/tmpx6lhcr3a/unpacked.gif'>
    ## which seem to be related to some pillow versions not correctly
    ## closing files.

    ## a test for the file being a single GIF
    def testFullfileIsGIF(self):
        filename = os.path.join(basetestdir, 'gif', 'test.gif')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

    ## a test for the file being a single GIF with data appended to it
    def testDataAppendedToGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-add-random-data.gif')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 7073713)

    ## a test for the file being a single GIF with data in front
    def testDataPrependedToGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-prepend-random-data.gif')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 7073713)

if __name__ == '__main__':
    unittest.main()
