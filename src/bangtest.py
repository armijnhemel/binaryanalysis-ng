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

## a test class for testing GIFs
class TestGIF(unittest.TestCase):

    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## Now all the test cases.

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

    ## a test for the file being a single GIF with data cut from the end
    def testDataCutFromEndGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-cut-data-from-end.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single GIF with data cut from the middle
    def testDataCutFromMiddleGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-cut-data-from-middle.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single GIF with data added in the middle
    def testDataAddedInMiddleGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-data-added-to-middle.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single GIF with data replaced in the middle
    def testDataReplacedInMiddleGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-data-replaced-in-middle.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

## a test class for testing PNG files
class TestPNG(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single PNG
    def testFullfileIsPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test.png')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

if __name__ == '__main__':
    unittest.main()
