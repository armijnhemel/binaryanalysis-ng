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
tmpdirectory = None

## a test class for testing GIFs
class TestGIF(unittest.TestCase):

    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

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
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

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

    ## a test for the file being a single PNG with data appended to it
    def testDataAppendedToPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-add-random-data.png')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 6001452)

    ## a test for the file being a single PNG with data in front
    def testDataPrependedToPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-prepend-random-data.png')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 6001452)

    ## a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-cut-data-from-end.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single PNG with data cut from the middle
    def testDataCutFromMiddlePNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-cut-data-from-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single PNG with data added in the middle
    def testDataAddedInMiddlePNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-data-added-to-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single PNG with data replaced in the middle
    def testDataReplacedInMiddlePNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-data-replaced-in-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

## a test class for testing JPEG files
class TestJPEG(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single JPEG
    def testFullfileIsJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test.jpg')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

    ## a test for the file being a single JPEG with data appended to it
    def testDataAppendedToJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-add-random-data.jpg')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 4676767)

    ## a test for the file being a single JPEG with data in front
    def testDataPrependedToJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-prepend-random-data.jpg')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 4676767)

    ## a test for the file being a single JPEG with data cut from the end
    def testDataCutFromEndJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-cut-data-from-end.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single JPEG with data cut from the middle
    def testDataCutFromMiddleJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-cut-data-from-middle.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single JPEG with data added in the middle
    def testDataAddedInMiddleJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-data-added-to-middle.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single JPEG with data replaced in the middle
    def testDataReplacedInMiddleJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-data-replaced-in-middle.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

## a test class for testing BMP files
class TestBMP(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single BMP
    def testFullfileIsBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test.bmp')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

    ## a test for the file being a single BMP with data appended to it
    def testDataAppendedToBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-add-random-data.bmp')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 572666)

    ## a test for the file being a single BMP with data in front
    def testDataPrependedToBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-prepend-random-data.bmp')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 572666)

    ## a test for the file being a single BMP with data cut from the end
    def testDataCutFromEndBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-cut-data-from-end.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single BMP with data cut from the middle
    def testDataCutFromMiddleBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-cut-data-from-middle.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single BMP with data added in the middle
    def testDataAddedInMiddleBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-data-added-to-middle.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single BMP with data replaced in the middle
    def testDataReplacedInMiddleBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-data-replaced-in-middle.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

## a test class for testing SGI files
class TestSGI(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single SGI
    def testFullfileIsSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

    ## now all the test cases.
    ## a test for the file being a single SGI
    def testFullfileIsSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

    ## a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-add-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 592418)

    ## a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-add-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 572048)

    ## a test for the file being a single SGI with data in front
    def testDataPrependedToSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-prepend-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 592418)

    ## a test for the file being a single SGI with data in front
    def testDataPrependedToSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-prepend-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], 572048)

    ## a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-cut-data-from-end.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-cut-data-from-end.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-cut-data-from-middle.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ## a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-cut-data-from-middle.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres[0])

    ### a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGI(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-data-added-to-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres[0])

    ## a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGIVerbatim(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-data-added-to-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres[0])

    ## a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGI(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-data-replaced-in-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres[0])

    ### a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGIVerbatim(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-data-replaced-in-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres[0])

if __name__ == '__main__':
    unittest.main()
