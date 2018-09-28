#!/usr/bin/python3

# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License,
# version 3, along with BANG.  If not, see <http://www.gnu.org/licenses/>
#
# Copyright 2018 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# Test modules for BANG
import unittest
import tempfile
import shutil
import os
import sys
import stat
import pathlib

# load own modules
import bangunpack

basetestdir = pathlib.Path('/home/armijn/git/binaryanalysis-ng/test')
tmpdirectory = '/home/armijn/tmp'


# a test class for testing GIFs
class TestGIF(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # Now all the test cases.

    # a test for the file being a single GIF
    def testFullfileIsGIF(self):
        filename = basetestdir / 'gif' / 'test.gif'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single GIF with data appended to it
    def testDataAppendedToGif(self):
        filename = basetestdir / 'gif' / 'test-add-random-data.gif'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 7073713)

    # a test for the file being a single GIF with data in front
    def testDataPrependedToGif(self):
        filename = basetestdir / 'gif' / 'test-prepend-random-data.gif'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 7073713)

    # a test for the file being a single GIF with data cut from the end
    def testDataCutFromEndGif(self):
        filename = basetestdir / 'gif' / 'test-cut-data-from-end.gif'
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data cut from the middle
    def testDataCutFromMiddleGif(self):
        filename = basetestdir / 'gif' / 'test-cut-data-from-middle.gif'
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data added in the middle
    def testDataAddedInMiddleGif(self):
        filename = basetestdir / 'gif' / 'test-data-added-to-middle.gif'
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data replaced in the middle
    def testDataReplacedInMiddleGif(self):
        filename = basetestdir / 'gif' / 'test-data-replaced-in-middle.gif'
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing PNG files
class TestPNG(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single PNG
    def testFullfileIsPNG(self):
        filename = basetestdir / 'png' / 'test.png'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single animated PNG
    def testFullfileIsAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball.png'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)
        self.assertIn('animated', testres['labels'])

    # a test for the file being a single PNG with data appended to it
    def testDataAppendedToPNG(self):
        filename = basetestdir / 'png' / 'test-add-random-data.png'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 6001452)

    # a test for the file being a single animated PNG with data appended to it
    def testDataAppendedToAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-add-random-data.png'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 63435)
        self.assertIn('animated', testres['filesandlabels'][0][1])

    # a test for the file being a single PNG with data in front
    def testDataPrependedToPNG(self):
        filename = basetestdir / 'png' / 'test-prepend-random-data.png'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 6001452)

    # a test for the file being a single animated PNG with data in front
    def testDataPrependedToAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-prepend-random-data.png'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 63435)
        self.assertIn('animated', testres['filesandlabels'][0][1])

    # a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndPNG(self):
        filename = basetestdir / 'png' / 'test-cut-data-from-end.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-end.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data cut from the middle
    def testDataCutFromMiddlePNG(self):
        filename = basetestdir / 'png' / 'test-cut-data-from-middle.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data cut from the middle
    def testDataCutFromMiddleAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-middle.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data added in the middle
    def testDataAddedInMiddlePNG(self):
        filename = basetestdir / 'png' / 'test-data-added-to-middle.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data added in the middle
    def testDataAddedInMiddleAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-data-added-to-middle.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data replaced in the middle
    def testDataReplacedInMiddlePNG(self):
        filename = basetestdir / 'png' / 'test-data-replaced-in-middle.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data replaced in the middle
    def testDataReplacedInMiddleAPNG(self):
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-data-replaced-in-middle.png'
        offset = 0
        testres = bangunpack.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing JPEG files
class TestJPEG(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single JPEG
    def testFullfileIsJPEG(self):
        filename = basetestdir / 'jpeg' / 'test.jpg'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single JPEG with data appended to it
    def testDataAppendedToJPEG(self):
        filename = basetestdir / 'jpeg' / 'test-add-random-data.jpg'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4676767)

    # a test for the file being a single JPEG with data in front
    def testDataPrependedToJPEG(self):
        filename = basetestdir / 'jpeg' / 'test-prepend-random-data.jpg'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4676767)

    # a test for the file being a single JPEG with data cut from the end
    def testDataCutFromEndJPEG(self):
        filename = basetestdir / 'jpeg' / 'test-cut-data-from-end.jpg'
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data cut from the middle
    def testDataCutFromMiddleJPEG(self):
        filename = basetestdir / 'jpeg' / 'test-cut-data-from-middle.jpg'
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data added in the middle
    def testDataAddedInMiddleJPEG(self):
        filename = basetestdir / 'jpeg' / 'test-data-added-to-middle.jpg'
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data replaced in the middle
    def testDataReplacedInMiddleJPEG(self):
        filename = basetestdir / 'jpeg' / 'test-data-replaced-in-middle.jpg'
        offset = 0
        testres = bangunpack.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing BMP files
class TestBMP(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single BMP
    def testFullfileIsBMP(self):
        filename = basetestdir / 'bmp' / 'test.bmp'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single BMP with data appended to it
    def testDataAppendedToBMP(self):
        filename = basetestdir / 'bmp' / 'test-add-random-data.bmp'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572666)

    # a test for the file being a single BMP with data in front
    def testDataPrependedToBMP(self):
        filename = basetestdir / 'bmp' / 'test-prepend-random-data.bmp'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572666)

    # a test for the file being a single BMP with data cut from the end
    def testDataCutFromEndBMP(self):
        filename = basetestdir / 'bmp' / 'test-cut-data-from-end.bmp'
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data cut from the middle
    def testDataCutFromMiddleBMP(self):
        filename = basetestdir / 'bmp' / 'test-cut-data-from-middle.bmp'
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data added in the middle
    def testDataAddedInMiddleBMP(self):
        filename = basetestdir / 'bmp' / 'test-data-added-to-middle.bmp'
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data replaced in the middle
    def testDataReplacedInMiddleBMP(self):
        filename = basetestdir / 'bmp' / 'test-data-replaced-in-middle.bmp'
        offset = 0
        testres = bangunpack.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing SGI files
class TestSGI(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single SGI
    def testFullfileIsSGI(self):
        filename = basetestdir / 'sgi' / 'test.sgi'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single SGI
    def testFullfileIsSGIVerbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim.sgi'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGI(self):
        filename = basetestdir / 'sgi' / 'test-add-random-data.sgi'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592418)

    # a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGIVerbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-add-random-data.sgi'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572048)

    # a test for the file being a single SGI with data in front
    def testDataPrependedToSGI(self):
        filename = basetestdir / 'sgi' / 'test-prepend-random-data.sgi'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592418)

    # a test for the file being a single SGI with data in front
    def testDataPrependedToSGIVerbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-prepend-random-data.sgi'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572048)

    # a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGI(self):
        filename = basetestdir / 'sgi' / 'test-cut-data-from-end.sgi'
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGIVerbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-cut-data-from-end.sgi'
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGI(self):
        filename = basetestdir / 'sgi' / 'test-cut-data-from-middle.sgi'
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGIVerbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-cut-data-from-middle.sgi'
        offset = 0
        testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGI(self):
    #    filename = basetestdir / 'sgi' / 'test-data-added-to-middle.sgi'
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGIVerbatim(self):
    #    filename = basetestdir / 'sgi' / 'test-verbatim-data-added-to-middle.sgi'
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGI(self):
    #    filename = basetestdir / 'sgi' / 'test-data-replaced-in-middle.sgi'
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGIVerbatim(self):
    #    filename = basetestdir / 'sgi' / 'test-verbatim-data-replaced-in-middle.sgi'
    #    offset = 0
    #    testres = bangunpack.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])


# a test class for testing Android sparse files
class TestAndroidSparse(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single Android sparse image
    def testFullfileIsAndroidSparse(self):
        filename = basetestdir / 'simg' / 'zero.img'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackAndroidSparse(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)


# a test class for testing SREC files
class TestSREC(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    def testSRECWrong(self):
        filename = basetestdir / 'srec' / 'srec-wrong.txt'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSREC(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing GZIP files
class TestGZIP(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single gzip
    def testFullfileIsGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg.gz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single gzip with data appended to it
    def testDataAppendedToGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg-add-random-data.gz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665601)

    # a test for the file being a single gzip with data in front
    def testDataPrependedToGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg-prepend-random-data.gz'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665601)

    # a test for the file being a single gzip with data cut from the end
    def testDataCutFromEndGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg-cut-data-from-end.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data cut from the middle
    def testDataCutFromMiddleGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg-cut-data-from-middle.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data added in the middle
    def testDataAddedInMiddleGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg-data-added-to-middle.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data replaced in the middle
    def testDataReplacedInMiddleGzip(self):
        filename = basetestdir / 'gzip' / 'test.jpg-data-replaced-in-middle.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing ZIP files
class TestZIP(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single ZIP
    def testFullfileIsZip(self):
        filename = basetestdir / 'zip' / 'test.zip'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single ZIP with data appended to it
    def testDataAppendedToZip(self):
        filename = basetestdir / 'zip' / 'test-add-random-data.zip'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665740)

    # a test for the file being a single ZIP with data in front
    def testDataPrependedToZip(self):
        filename = basetestdir / 'zip' / 'test-prepend-random-data.zip'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665740)

    # a test for the file being a single ZIP with data cut from the end
    def testDataCutFromEndZip(self):
        filename = basetestdir / 'zip' / 'test-cut-data-from-end.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data cut from the middle
    def testDataCutFromMiddleZip(self):
        filename = basetestdir / 'zip' / 'test-cut-data-from-middle.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data added in the middle
    def testDataAddedInMiddleZip(self):
        filename = basetestdir / 'zip' / 'test-data-added-to-middle.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data replaced in the middle
    def testDataReplacedInMiddleZip(self):
        filename = basetestdir / 'zip' / 'test-data-replaced-in-middle.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing LZ4 files
class TestLZ4(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single LZ4
    def testFullfileIsLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt.lz4'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single LZ4 with data appended to it
    def testDataAppendedToLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-add-random-data.lz4'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 755644)

    # a test for the file being a single LZ4 with data in front
    def testDataPrependedToLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-prepend-random-data.lz4'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 755644)

    # a test for the file being a single LZ4 with data cut from the end
    def testDataCutFromEndLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-cut-data-from-end.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data cut from the middle
    def testDataCutFromMiddleLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-cut-data-from-middle.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data added in the middle
    def testDataAddedInMiddleLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-data-added-to-middle.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data replaced in the middle
    def testDataReplacedInMiddleLZ4(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-data-replaced-in-middle.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing CPIO files
class TestCPIO(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single CPIO
    def testFullfileIsCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def testFullfileIsCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def testFullfileIsCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def testFullfileIsCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-add-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old-add-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new-add-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc-add-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-prepend-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old-prepend-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new-prepend-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc-prepend-random-data.cpio'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOBin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOOld(self):
        filename = basetestdir / 'cpio' / 'test-old-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIONew(self):
        filename = basetestdir / 'cpio' / 'test-new-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOCRC(self):
        filename = basetestdir / 'cpio' / 'test-crc-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing XZ files
class TestXZ(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single XZ
    def testFullfileIsXZ(self):
        filename = basetestdir / 'xz' / 'test.xz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single XZ with data appended to it
    def testDataAppendedToXZ(self):
        filename = basetestdir / 'xz' / 'test-add-random-data.xz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510744)

    # a test for the file being a single XZ with data in front
    def testDataPrependedToXZ(self):
        filename = basetestdir / 'xz' / 'test-prepend-random-data.xz'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510744)

    # a test for the file being a single XZ with data cut from the end
    def testDataCutFromEndXZ(self):
        filename = basetestdir / 'xz' / 'test-cut-data-from-end.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data cut from the middle
    def testDataCutFromMiddleXZ(self):
        filename = basetestdir / 'xz' / 'test-cut-data-from-middle.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data added in the middle
    def testDataAddedInMiddleXZ(self):
        filename = basetestdir / 'xz' / 'test-data-added-to-middle.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data replaced in the middle
    def testDataReplacedInMiddleXZ(self):
        filename = basetestdir / 'xz' / 'test-data-replaced-in-middle.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing LZMA files
class TestLZMA(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single LZMA
    def testFullfileIsLZMA(self):
        filename = basetestdir / 'lzma' / 'test.lzma'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single LZMA with data appended to it
    def testDataAppendedToLZMA(self):
        filename = basetestdir / 'lzma' / 'test-add-random-data.lzma'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510623)

    # a test for the file being a single LZMA with data in front
    def testDataPrependedToLZMA(self):
        filename = basetestdir / 'lzma' / 'test-prepend-random-data.lzma'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510623)

    # a test for the file being a single LZMA with data cut from the end
    def testDataCutFromEndLZMA(self):
        filename = basetestdir / 'lzma' / 'test-cut-data-from-end.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data cut from the middle
    def testDataCutFromMiddleLZMA(self):
        filename = basetestdir / 'lzma' / 'test-cut-data-from-middle.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data added in the middle
    def testDataAddedInMiddleLZMA(self):
        filename = basetestdir / 'lzma' / 'test-data-added-to-middle.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data replaced in the middle
    def testDataReplacedInMiddleLZMA(self):
        filename = basetestdir / 'lzma' / 'test-data-replaced-in-middle.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing bzip2 files
class TestBzip2(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single bzip2
    def testFullfileIsBzip2(self):
        filename = basetestdir / 'bz2' / 'test.bz2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single bzip2 with data appended to it
    def testDataAppendedToBzip2(self):
        filename = basetestdir / 'bz2' / 'test-add-random-data.bz2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530237)

    # a test for the file being a single bzip2 with data in front
    def testDataPrependedToBzip2(self):
        filename = basetestdir / 'bz2' / 'test-prepend-random-data.bz2'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530237)

    # a test for the file being a single bzip2 with data cut from the end
    def testDataCutFromEndBzip2(self):
        filename = basetestdir / 'bz2' / 'test-cut-data-from-end.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data cut from the middle
    def testDataCutFromMiddleBzip2(self):
        filename = basetestdir / 'bz2' / 'test-cut-data-from-middle.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data added in the middle
    def testDataAddedInMiddleBzip2(self):
        filename = basetestdir / 'bz2' / 'test-data-added-to-middle.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data replaced in the middle
    def testDataReplacedInMiddleBzip2(self):
        filename = basetestdir / 'bz2' / 'test-data-replaced-in-middle.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing lzip files
class TestLzip(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single lzip
    def testFullfileIsLzip(self):
        filename = basetestdir / 'lzip' / 'test.lz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single lzip with data appended to it
    def testDataAppendedToLzip(self):
        filename = basetestdir / 'lzip' / 'test-add-random-data.lz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511095)

    # a test for the file being a single lzip with data in front
    def testDataPrependedToLzip(self):
        filename = basetestdir / 'lzip' / 'test-prepend-random-data.lz'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511095)

    # a test for the file being a single lzip with data cut from the end
    def testDataCutFromEndLzip(self):
        filename = basetestdir / 'lzip' / 'test-cut-data-from-end.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data cut from the middle
    def testDataCutFromMiddleLzip(self):
        filename = basetestdir / 'lzip' / 'test-cut-data-from-middle.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data added in the middle
    def testDataAddedInMiddleLzip(self):
        filename = basetestdir / 'lzip' / 'test-data-added-to-middle.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data replaced in the middle
    def testDataReplacedInMiddleLzip(self):
        filename = basetestdir / 'lzip' / 'test-data-replaced-in-middle.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing zstd files
class TestZstd(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single zstd
    def testFullfileIsZstd(self):
        filename = basetestdir / 'zstd' / 'test.zst'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single zstd with data appended to it
    def testDataAppendedToZstd(self):
        filename = basetestdir / 'zstd' / 'test-add-random-data.zst'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 583703)

    # a test for the file being a single zstd with data in front
    def testDataPrependedToZstd(self):
        filename = basetestdir / 'zstd' / 'test-prepend-random-data.zst'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 583703)

    # a test for the file being a single zstd with data cut from the end
    def testDataCutFromEndZstd(self):
        filename = basetestdir / 'zstd' / 'test-cut-data-from-end.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data cut from the middle
    def testDataCutFromMiddleZstd(self):
        filename = basetestdir / 'zstd' / 'test-cut-data-from-middle.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data added in the middle
    def testDataAddedInMiddleZstd(self):
        filename = basetestdir / 'zstd' / 'test-data-added-to-middle.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data replaced in the middle
    def testDataReplacedInMiddleZstd(self):
        filename = basetestdir / 'zstd' / 'test-data-replaced-in-middle.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing 7z files
class Test7z(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single 7z
    def testFullfileIs7z(self):
        filename = basetestdir / '7z' / 'test.7z'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single 7z with data appended to it
    def testDataAppendedTo7z(self):
        filename = basetestdir / '7z' / 'test-add-random-data.7z'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511498)

    # a test for the file being a single 7z with data in front
    def testDataPrependedTo7z(self):
        filename = basetestdir / '7z' / 'test-prepend-random-data.7z'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511498)

    # a test for the file being a single 7z with data cut from the end
    def testDataCutFromEnd7z(self):
        filename = basetestdir / '7z' / 'test-cut-data-from-end.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data cut from the middle
    def testDataCutFromMiddle7z(self):
        filename = basetestdir / '7z' / 'test-cut-data-from-middle.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data added in the middle
    def testDataAddedInMiddle7z(self):
        filename = basetestdir / '7z' / 'test-data-added-to-middle.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data replaced in the middle
    def testDataReplacedInMiddle7z(self):
        filename = basetestdir / '7z' / 'test-data-replaced-in-middle.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing ar files
class TestAr(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single ar
    def testFullfileIsAr(self):
        filename = basetestdir / 'ar' / 'test.ar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single ar with data appended to it
    def testDataAppendedToAr(self):
        filename = basetestdir / 'ar' / 'test-add-random-data.ar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)

        # ar unpacker only works on complete files
        self.assertFalse(testres['status'])
        #self.assertTrue(testres['status'])
        #self.assertEqual(testres['length'], 511498)

    # a test for the file being a single ar with data in front
    def testDataPrependedToAr(self):
        filename = basetestdir / 'ar' / 'test-prepend-random-data.ar'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)

        # ar unpacker only works on complete files
        self.assertFalse(testres['status'])
        #self.assertTrue(testres['status'])
        #self.assertEqual(testres['length'], 511498)

    # a test for the file being a single ar with data cut from the end
    def testDataCutFromEndAr(self):
        filename = basetestdir / 'ar' / 'test-cut-data-from-end.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data cut from the middle
    def testDataCutFromMiddleAr(self):
        filename = basetestdir / 'ar' / 'test-cut-data-from-middle.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data added in the middle
    def testDataAddedInMiddleAr(self):
        filename = basetestdir / 'ar' / 'test-data-added-to-middle.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data replaced in the middle
    def testDataReplacedInMiddleAr(self):
        filename = basetestdir / 'ar' / 'test-data-replaced-in-middle.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing XAR files
class TestXAR(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single xar
    def testFullfileIsXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single xar
    def testFullfileIsXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single xar
    def testFullfileIsXARNone(self):
        filename = basetestdir / 'xar' / 'test-none.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single xar with data appended to it
    def testDataAppendedToXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip-add-random-data.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 582324)

    # a test for the file being a single xar with data appended to it
    def testDataAppendedToXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-add-random-data.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530707)

    # a test for the file being a single xar with data appended to it
    def testDataAppendedToXARNone(self):
        filename = basetestdir / 'xar' / 'test-none-add-random-data.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592861)

    # a test for the file being a single xar with data in front
    def testDataPrependedToXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip-prepend-random-data.xar'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 582324)

    # a test for the file being a single xar with data in front
    def testDataPrependedToXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-prepend-random-data.xar'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530707)

    # a test for the file being a single xar with data in front
    def testDataPrependedToXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-none-prepend-random-data.xar'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592861)

    # a test for the file being a single xar with data cut from the end
    def testDataCutFromEndXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip-cut-data-from-end.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the end
    def testDataCutFromEndXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-cut-data-from-end.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the end
    def testDataCutFromEndXARNone(self):
        filename = basetestdir / 'xar' / 'test-none-cut-data-from-end.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def testDataCutFromMiddleXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip-cut-data-from-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def testDataCutFromMiddleXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-cut-data-from-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def testDataCutFromMiddleXARNone(self):
        filename = basetestdir / 'xar' / 'test-none-cut-data-from-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def testDataAddedInMiddleXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip-data-added-to-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def testDataAddedInMiddleXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-data-added-to-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def testDataAddedInMiddleXARNone(self):
        filename = basetestdir / 'xar' / 'test-none-data-added-to-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def testDataReplacedInMiddleXAR(self):
        filename = basetestdir / 'xar' / 'test-gzip-data-replaced-in-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def testDataReplacedInMiddleXARBzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-data-replaced-in-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def testDataReplacedInMiddleXARNone(self):
        filename = basetestdir / 'xar' / 'test-none-data-replaced-in-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing squashfs files
class TestSquashfs(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single squashfs
    def testFullfileIsSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test.sqsh'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single squashfs with data appended to it
    def testDataAppendedToSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test-add-random-data.sqsh'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 577536)

    # a test for the file being a single squashfs with data in front
    def testDataPrependedToSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test-prepend-random-data.sqsh'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 577536)

    # a test for the file being a single squashfs with data cut from the end
    def testDataCutFromEndSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test-cut-data-from-end.sqsh'
        offset = 0
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs with data cut from the middle
    def testDataCutFromMiddleSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test-cut-data-from-middle.sqsh'
        offset = 0
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs with data added in the middle
    def testDataAddedInMiddleSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test-data-added-to-middle.sqsh'
        offset = 0
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs
    # with data replaced in the middle
    def testDataReplacedInMiddleSquashfs(self):
        filename = basetestdir / 'squashfs' / 'test-data-replaced-in-middle.sqsh'
        offset = 0
        testres = bangunpack.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing snappy files
class TestSnappy(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single snappy
    def testFullfileIsSnappy(self):
        filename = basetestdir / 'snappy' / 'test.sz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single snappy with data appended to it
    def testDataAppendedToSnappy(self):
        filename = basetestdir / 'snappy' / 'test-add-random-data.sz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592508)

    # a test for the file being a single snappy with data in front
    def testDataPrependedToSnappy(self):
        filename = basetestdir / 'snappy' / 'test-prepend-random-data.sz'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592508)

    # a test for the file being a single snappy with data cut from the end
    def testDataCutFromEndSnappy(self):
        filename = basetestdir / 'snappy' / 'test-cut-data-from-end.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy with data cut from the middle
    def testDataCutFromMiddleSnappy(self):
        filename = basetestdir / 'snappy' / 'test-cut-data-from-middle.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy with data added in the middle
    def testDataAddedInMiddleSnappy(self):
        filename = basetestdir / 'snappy' / 'test-data-added-to-middle.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy
    # with data replaced in the middle
    def testDataReplacedInMiddleSnappy(self):
        filename = basetestdir / 'snappy' / 'test-data-replaced-in-middle.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing ISO files
class TestISO9660(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single iso9660
    def testFullfileIsISO9660(self):
        filename = basetestdir / 'iso9660' / 'test.iso'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single iso9660 with data appended to it
    def testDataAppendedToISO9660(self):
        filename = basetestdir / 'iso9660' / 'test-add-random-data.iso'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 952320)

    # a test for the file being a single iso9660 with data in front
    def testDataPrependedToISO9660(self):
        filename = basetestdir / 'iso9660' / 'test-prepend-random-data.iso'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 952320)

    # a test for the file being a single iso9660 with data cut from the end
    def testDataCutFromEndISO9660(self):
        filename = basetestdir / 'iso9660' / 'test-cut-data-from-end.iso'
        offset = 0
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660 with data cut from the middle
    def testDataCutFromMiddleISO9660(self):
        filename = basetestdir / 'iso9660' / 'test-cut-data-from-middle.iso'
        offset = 0
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660 with data added in the middle
    def testDataAddedInMiddleISO9660(self):
        filename = basetestdir / 'iso9660' / 'test-data-added-to-middle.iso'
        offset = 0
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660
    # with data replaced in the middle
    def testDataReplacedInMiddleISO9660(self):
        filename = basetestdir / 'iso9660' / 'test-data-replaced-in-middle.iso'
        offset = 0
        testres = bangunpack.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing tar files
class TestTar(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single tar
    def testFullfileIsTar(self):
        filename = basetestdir / 'tar' / 'test.tar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single tar with data appended to it
    def testDataAppendedToTar(self):
        filename = basetestdir / 'tar' / 'test-add-random-data.tar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 604160)

    # a test for the file being a single tar with data in front
    def testDataPrependedToTar(self):
        filename = basetestdir / 'tar' / 'test-prepend-random-data.tar'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 604160)

    # a test for the file being a single tar with data cut from the end
    def testDataCutFromEndTar(self):
        filename = basetestdir / 'tar' / 'test-cut-data-from-end.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data cut from the middle
    def testDataCutFromMiddleTar(self):
        filename = basetestdir / 'tar' / 'test-cut-data-from-middle.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data added in the middle
    def testDataAddedInMiddleTar(self):
        filename = basetestdir / 'tar' / 'test-data-added-to-middle.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data replaced in the middle
    def testDataReplacedInMiddleTar(self):
        filename = basetestdir / 'tar' / 'test-data-replaced-in-middle.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with just directories
    def testFullfileIsTarDir(self):
        filename = basetestdir / 'tar' / 'test-dir.tar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 10240)


# a test class for testing jffs2 files
class TestJFFS2(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single jffs2
    def testFullfileIsJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little.jffs2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single jffs2
    def testFullfileIsJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big.jffs2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single jffs2 with data appended to it
    def testDataAppendedToJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little-add-random-data.jffs2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data appended to it
    def testDataAppendedToJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big-add-random-data.jffs2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data in front
    def testDataPrependedToJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little-prepend-random-data.jffs2'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data in front
    def testDataPrependedToJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big-prepend-random-data.jffs2'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data cut from the end
    def testDataCutFromEndJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little-cut-data-from-end.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the end
    def testDataCutFromEndJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big-cut-data-from-end.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the middle
    def testDataCutFromMiddleJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little-cut-data-from-middle.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the middle
    def testDataCutFromMiddleJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big-cut-data-from-middle.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data added in the middle
    def testDataAddedInMiddleJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little-data-added-to-middle.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data added in the middle
    def testDataAddedInMiddleJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big-data-added-to-middle.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data replaced in the middle
    def testDataReplacedInMiddleJFFS2Little(self):
        filename = basetestdir / 'jffs2' / 'test-little-data-replaced-in-middle.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data replaced in the middle
    def testDataReplacedInMiddleJFFS2Big(self):
        filename = basetestdir / 'jffs2' / 'test-big-data-replaced-in-middle.jffs2'
        offset = 0
        testres = bangunpack.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing rzip files
class TestRzip(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single rzip
    def testFullfileIsRzip(self):
        filename = basetestdir / 'rzip' / 'test.rz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single rzip with data appended to it
    def testDataAppendedToRzip(self):
        filename = basetestdir / 'rzip' / 'test-add-random-data.rz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530499)

    # a test for the file being a single rzip with data in front
    def testDataPrependedToRzip(self):
        filename = basetestdir / 'rzip' / 'test-prepend-random-data.rz'
        filesize = filename.stat().st_size
        offset = 128
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530499)

    # a test for the file being a single rzip with data cut from the end
    def testDataCutFromEndRzip(self):
        filename = basetestdir / 'rzip' / 'test-cut-data-from-end.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data cut from the middle
    def testDataCutFromMiddleRzip(self):
        filename = basetestdir / 'rzip' / 'test-cut-data-from-middle.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data added in the middle
    def testDataAddedInMiddleRzip(self):
        filename = basetestdir / 'rzip' / 'test-data-added-to-middle.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data replaced in the middle
    def testDataReplacedInMiddleRzip(self):
        filename = basetestdir / 'rzip' / 'test-data-replaced-in-middle.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

if __name__ == '__main__':
    unittest.main()
