#!/usr/bin/python3

## Binary Analysis Next Generation (BANG!)
##
## This file is part of BANG.
##
## BANG is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License, version 3,
## as published by the Free Software Foundation.
##
## BANG is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License for more details.
##
## You should have received a copy of the GNU Affero General Public License, version 3,
## along with BANG.  If not, see <http://www.gnu.org/licenses/>
##
## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU Affero General Public License version 3
## SPDX-License-Identifier: AGPL-3.0-only

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
tmpdirectory = '/home/armijn/tmp'

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
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single GIF with data appended to it
    def testDataAppendedToGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-add-random-data.gif')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 7073713)

    ## a test for the file being a single GIF with data in front
    def testDataPrependedToGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-prepend-random-data.gif')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 7073713)

    ## a test for the file being a single GIF with data cut from the end
    def testDataCutFromEndGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-cut-data-from-end.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single GIF with data cut from the middle
    def testDataCutFromMiddleGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-cut-data-from-middle.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single GIF with data added in the middle
    def testDataAddedInMiddleGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-data-added-to-middle.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single GIF with data replaced in the middle
    def testDataReplacedInMiddleGif(self):
        filename = os.path.join(basetestdir, 'gif', 'test-data-replaced-in-middle.gif')
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

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
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single animated PNG
    def testFullfileIsAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball.png')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)
        self.assertIn('animated', unpackedlabels)

    ## a test for the file being a single PNG with data appended to it
    def testDataAppendedToPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-add-random-data.png')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 6001452)

    ## a test for the file being a single animated PNG with data appended to it
    def testDataAppendedToAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball-add-random-data.png')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 63435)
        self.assertIn('animated', unpackedfilesandlabels[0][1])

    ## a test for the file being a single PNG with data in front
    def testDataPrependedToPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-prepend-random-data.png')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 6001452)

    ## a test for the file being a single animated PNG with data in front
    def testDataPrependedToAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball-prepend-random-data.png')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 63435)
        self.assertIn('animated', unpackedfilesandlabels[0][1])

    ## a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndPNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-cut-data-from-end.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-end.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single PNG with data cut from the middle
    def testDataCutFromMiddlePNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-cut-data-from-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single animated PNG with data cut from the middle
    def testDataCutFromMiddleAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single PNG with data added in the middle
    def testDataAddedInMiddlePNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-data-added-to-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single animated PNG with data added in the middle
    def testDataAddedInMiddleAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball-data-added-to-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single PNG with data replaced in the middle
    def testDataReplacedInMiddlePNG(self):
        filename = os.path.join(basetestdir, 'png', 'test-data-replaced-in-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single animated PNG with data replaced in the middle
    def testDataReplacedInMiddleAPNG(self):
        filename = os.path.join(basetestdir, 'png', 'Animated_PNG_example_bouncing_beach_ball-data-replaced-in-middle.png')
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

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
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single JPEG with data appended to it
    def testDataAppendedToJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-add-random-data.jpg')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 4676767)

    ## a test for the file being a single JPEG with data in front
    def testDataPrependedToJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-prepend-random-data.jpg')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 4676767)

    ## a test for the file being a single JPEG with data cut from the end
    def testDataCutFromEndJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-cut-data-from-end.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single JPEG with data cut from the middle
    def testDataCutFromMiddleJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-cut-data-from-middle.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single JPEG with data added in the middle
    def testDataAddedInMiddleJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-data-added-to-middle.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single JPEG with data replaced in the middle
    def testDataReplacedInMiddleJPEG(self):
        filename = os.path.join(basetestdir, 'jpeg', 'test-data-replaced-in-middle.jpg')
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

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
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single BMP with data appended to it
    def testDataAppendedToBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-add-random-data.bmp')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 572666)

    ## a test for the file being a single BMP with data in front
    def testDataPrependedToBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-prepend-random-data.bmp')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 572666)

    ## a test for the file being a single BMP with data cut from the end
    def testDataCutFromEndBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-cut-data-from-end.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single BMP with data cut from the middle
    def testDataCutFromMiddleBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-cut-data-from-middle.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single BMP with data added in the middle
    def testDataAddedInMiddleBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-data-added-to-middle.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single BMP with data replaced in the middle
    def testDataReplacedInMiddleBMP(self):
        filename = os.path.join(basetestdir, 'bmp', 'test-data-replaced-in-middle.bmp')
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

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
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## now all the test cases.
    ## a test for the file being a single SGI
    def testFullfileIsSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-add-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592418)

    ## a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-add-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 572048)

    ## a test for the file being a single SGI with data in front
    def testDataPrependedToSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-prepend-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592418)

    ## a test for the file being a single SGI with data in front
    def testDataPrependedToSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-prepend-random-data.sgi')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 572048)

    ## a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-cut-data-from-end.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-cut-data-from-end.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGI(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-cut-data-from-middle.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGIVerbatim(self):
        filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-cut-data-from-middle.sgi')
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ### a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGI(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-data-added-to-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
    #    self.assertFalse(unpackstatus)

    ## a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGIVerbatim(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-data-added-to-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
    #    self.assertFalse(unpackstatus)

    ## a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGI(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-data-replaced-in-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
    #    self.assertFalse(unpackstatus)

    ### a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGIVerbatim(self):
    #    filename = os.path.join(basetestdir, 'sgi', 'test-verbatim-data-replaced-in-middle.sgi')
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
    #    self.assertFalse(unpackstatus)

## a test class for testing Android sparse files
class TestAndroidSparse(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single Android sparse image
    def testFullfileIsAndroidSparse(self):
        filename = os.path.join(basetestdir, 'simg', 'zero.img')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackAndroidSparse(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

## a test class for testing SREC files
class TestSREC(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    def testSRECWrong(self):
        filename = os.path.join(basetestdir, 'srec', 'srec-wrong.txt')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackSREC(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing GZIP files
class TestGZIP(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single gzip
    def testFullfileIsGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg.gz')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single gzip with data appended to it
    def testDataAppendedToGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg-add-random-data.gz')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 4665601)

    ## a test for the file being a single gzip with data in front
    def testDataPrependedToGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg-prepend-random-data.gz')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 4665601)

    ## a test for the file being a single gzip with data cut from the end
    def testDataCutFromEndGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg-cut-data-from-end.gz')
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single gzip with data cut from the middle
    def testDataCutFromMiddleGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg-cut-data-from-middle.gz')
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single gzip with data added in the middle
    def testDataAddedInMiddleGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg-data-added-to-middle.gz')
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single gzip with data replaced in the middle
    def testDataReplacedInMiddleGzip(self):
        filename = os.path.join(basetestdir, 'gzip', 'test.jpg-data-replaced-in-middle.gz')
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing ZIP files
class TestZIP(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single ZIP
    def testFullfileIsZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test.zip')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single ZIP with data appended to it
    def testDataAppendedToZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test-add-random-data.zip')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 4665740)

    ## a test for the file being a single ZIP with data in front
    def testDataPrependedToZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test-prepend-random-data.zip')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 4665740)

    ## a test for the file being a single ZIP with data cut from the end
    def testDataCutFromEndZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test-cut-data-from-end.zip')
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single ZIP with data cut from the middle
    def testDataCutFromMiddleZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test-cut-data-from-middle.zip')
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single ZIP with data added in the middle
    def testDataAddedInMiddleZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test-data-added-to-middle.zip')
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single ZIP with data replaced in the middle
    def testDataReplacedInMiddleZip(self):
        filename = os.path.join(basetestdir, 'zip', 'test-data-replaced-in-middle.zip')
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing LZ4 files
class TestLZ4(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single LZ4
    def testFullfileIsLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt.lz4')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single LZ4 with data appended to it
    def testDataAppendedToLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt-add-random-data.lz4')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 755644)

    ## a test for the file being a single LZ4 with data in front
    def testDataPrependedToLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt-prepend-random-data.lz4')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 755644)

    ## a test for the file being a single LZ4 with data cut from the end
    def testDataCutFromEndLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt-cut-data-from-end.lz4')
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single LZ4 with data cut from the middle
    def testDataCutFromMiddleLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt-cut-data-from-middle.lz4')
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single LZ4 with data added in the middle
    def testDataAddedInMiddleLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt-data-added-to-middle.lz4')
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single LZ4 with data replaced in the middle
    def testDataReplacedInMiddleLZ4(self):
        filename = os.path.join(basetestdir, 'lz4', 'pg6130.txt-data-replaced-in-middle.lz4')
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing CPIO files
class TestCPIO(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single CPIO
    def testFullfileIsCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single CPIO
    def testFullfileIsCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single CPIO
    def testFullfileIsCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single CPIO
    def testFullfileIsCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin-add-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-add-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new-add-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc-add-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin-prepend-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-prepend-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new-prepend-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc-prepend-random-data.cpio')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 592896)

    ## a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin-cut-data-from-end.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-cut-data-from-end.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new-cut-data-from-end.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc-cut-data-from-end.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin-cut-data-from-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-cut-data-from-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new-cut-data-from-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc-cut-data-from-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin-data-added-to-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-data-added-to-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new-data-added-to-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc-data-added-to-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOBin(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-bin-data-replaced-in-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOOld(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-old-data-replaced-in-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIONew(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-new-data-replaced-in-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOCRC(self):
        filename = os.path.join(basetestdir, 'cpio', 'test-crc-data-replaced-in-middle.cpio')
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing XZ files
class TestXZ(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single XZ
    def testFullfileIsXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test.xz')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single XZ with data appended to it
    def testDataAppendedToXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test-add-random-data.xz')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 510744)

    ## a test for the file being a single XZ with data in front
    def testDataPrependedToXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test-prepend-random-data.xz')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 510744)

    ## a test for the file being a single XZ with data cut from the end
    def testDataCutFromEndXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test-cut-data-from-end.xz')
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single XZ with data cut from the middle
    def testDataCutFromMiddleXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test-cut-data-from-middle.xz')
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single XZ with data added in the middle
    def testDataAddedInMiddleXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test-data-added-to-middle.xz')
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single XZ with data replaced in the middle
    def testDataReplacedInMiddleXZ(self):
        filename = os.path.join(basetestdir, 'xz', 'test-data-replaced-in-middle.xz')
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing LZMA files
class TestLZMA(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single LZMA
    def testFullfileIsLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test.lzma')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single LZMA with data appended to it
    def testDataAppendedToLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test-add-random-data.lzma')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 510623)

    ## a test for the file being a single LZMA with data in front
    def testDataPrependedToLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test-prepend-random-data.lzma')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 510623)

    ## a test for the file being a single LZMA with data cut from the end
    def testDataCutFromEndLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test-cut-data-from-end.lzma')
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single LZMA with data cut from the middle
    def testDataCutFromMiddleLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test-cut-data-from-middle.lzma')
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single LZMA with data added in the middle
    def testDataAddedInMiddleLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test-data-added-to-middle.lzma')
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single LZMA with data replaced in the middle
    def testDataReplacedInMiddleLZMA(self):
        filename = os.path.join(basetestdir, 'lzma', 'test-data-replaced-in-middle.lzma')
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing bzip2 files
class TestBzip2(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single bzip2
    def testFullfileIsBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test.bz2')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single bzip2 with data appended to it
    def testDataAppendedToBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test-add-random-data.bz2')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 530237)

    ## a test for the file being a single bzip2 with data in front
    def testDataPrependedToBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test-prepend-random-data.bz2')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 530237)

    ## a test for the file being a single bzip2 with data cut from the end
    def testDataCutFromEndBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test-cut-data-from-end.bz2')
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single bzip2 with data cut from the middle
    def testDataCutFromMiddleBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test-cut-data-from-middle.bz2')
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single bzip2 with data added in the middle
    def testDataAddedInMiddleBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test-data-added-to-middle.bz2')
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single bzip2 with data replaced in the middle
    def testDataReplacedInMiddleBzip2(self):
        filename = os.path.join(basetestdir, 'bz2', 'test-data-replaced-in-middle.bz2')
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing lzip files
class TestLzip(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single lzip
    def testFullfileIsLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test.lz')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single lzip with data appended to it
    def testDataAppendedToLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test-add-random-data.lz')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 511095)

    ## a test for the file being a single lzip with data in front
    def testDataPrependedToLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test-prepend-random-data.lz')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 511095)

    ## a test for the file being a single lzip with data cut from the end
    def testDataCutFromEndLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test-cut-data-from-end.lz')
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single lzip with data cut from the middle
    def testDataCutFromMiddleLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test-cut-data-from-middle.lz')
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single lzip with data added in the middle
    def testDataAddedInMiddleLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test-data-added-to-middle.lz')
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single lzip with data replaced in the middle
    def testDataReplacedInMiddleLzip(self):
        filename = os.path.join(basetestdir, 'lzip', 'test-data-replaced-in-middle.lz')
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing zstd files
class TestZstd(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single zstd
    def testFullfileIsZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test.zst')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single zstd with data appended to it
    def testDataAppendedToZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test-add-random-data.zst')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 583703)

    ## a test for the file being a single zstd with data in front
    def testDataPrependedToZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test-prepend-random-data.zst')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 583703)

    ## a test for the file being a single zstd with data cut from the end
    def testDataCutFromEndZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test-cut-data-from-end.zst')
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single zstd with data cut from the middle
    def testDataCutFromMiddleZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test-cut-data-from-middle.zst')
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single zstd with data added in the middle
    def testDataAddedInMiddleZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test-data-added-to-middle.zst')
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single zstd with data replaced in the middle
    def testDataReplacedInMiddleZstd(self):
        filename = os.path.join(basetestdir, 'zstd', 'test-data-replaced-in-middle.zst')
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

## a test class for testing 7z files
class Test7z(unittest.TestCase):
    ## create a temporary directory and copy
    ## the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    ## remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    ## now all the test cases.
    ## a test for the file being a single 7z
    def testFullfileIs7z(self):
        filename = os.path.join(basetestdir, '7z', 'test.7z')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, filesize)

    ## a test for the file being a single 7z with data appended to it
    def testDataAppendedTo7z(self):
        filename = os.path.join(basetestdir, '7z', 'test-add-random-data.7z')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 511498)

    ## a test for the file being a single 7z with data in front
    def testDataPrependedTo7z(self):
        filename = os.path.join(basetestdir, '7z', 'test-prepend-random-data.7z')
        filesize = os.stat(filename).st_size
        offset = 128
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertTrue(unpackstatus)
        self.assertEqual(unpackedlength, 511498)

    ## a test for the file being a single 7z with data cut from the end
    def testDataCutFromEnd7z(self):
        filename = os.path.join(basetestdir, '7z', 'test-cut-data-from-end.7z')
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single 7z with data cut from the middle
    def testDataCutFromMiddle7z(self):
        filename = os.path.join(basetestdir, '7z', 'test-cut-data-from-middle.7z')
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single 7z with data added in the middle
    def testDataAddedInMiddle7z(self):
        filename = os.path.join(basetestdir, '7z', 'test-data-added-to-middle.7z')
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

    ## a test for the file being a single 7z with data replaced in the middle
    def testDataReplacedInMiddle7z(self):
        filename = os.path.join(basetestdir, '7z', 'test-data-replaced-in-middle.7z')
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        (unpackstatus, unpackedlength, unpackedfilesandlabels, unpackedlabels, unpackerror) = testres
        self.assertFalse(unpackstatus)

if __name__ == '__main__':
    unittest.main()
