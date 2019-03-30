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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

# Test modules for BANG
import unittest
import tempfile
import shutil
import pathlib
import os
import sys

_scriptdir = os.path.dirname(__file__)
sys.path.insert(0,os.path.join(_scriptdir,'..'))

# load own modules
import bangunpack
import bangfilesystems
import bangmedia
import bangandroid

# basetestdir = pathlib.Path('/home/armijn/git/binaryanalysis-ng/test')
# tmpdirectory = '/home/armijn/tmp'

from TestUtil import *

# a test class for testing GIFs
class TestGIF(TestBase):

    # a test for the file being a single GIF
    def testFullfileIsGIF(self):
        '''Test a single GIF'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test.gif'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single GIF with data appended to it
    def testDataAppendedToGif(self):
        '''Test a single GIF with data appended'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test-add-random-data.gif'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 7073713)

    # a test for the file being a single GIF with data in front
    def testDataPrependedToGif(self):
        '''Test a single GIF with data prepended'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test-prepend-random-data.gif'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 7073713)

    # a test for the file being a single GIF with data cut from the end
    def testDataCutFromEndGif(self):
        '''Test a single GIF with data cut from the end'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test-cut-data-from-end.gif'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data cut from the middle
    def testDataCutFromMiddleGif(self):
        '''Test a single GIF with data cut from the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test-cut-data-from-middle.gif'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data added in the middle
    def testDataAddedInMiddleGif(self):
        '''Test a single GIF with data added in the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test-data-added-to-middle.gif'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data replaced in the middle
    def testDataReplacedInMiddleGif(self):
        '''Test a single GIF with data replaced in the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gif' / 'test-data-replaced-in-middle.gif'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackGIF(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing PNG files
class TestPNG(TestBase):
    # a test for the file being a single PNG
    def testFullfileIsPNG(self):
        '''Test a single PNG'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test.png'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single animated PNG
    def testFullfileIsAPNG(self):
        '''Test a single animated PNG'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball.png'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)
        self.assertIn('animated', testres['labels'])

    # a test for the file being a single PNG with data appended to it
    def testDataAppendedToPNG(self):
        '''Test a single PNG with data appended'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test-add-random-data.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 6001452)

    # a test for the file being a single animated PNG with data appended to it
    def testDataAppendedToAPNG(self):
        '''Test a single animated PNG with data appended'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball-add-random-data.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 63435)
        self.assertIn('animated', testres['filesandlabels'][0][1])

    # a test for the file being a single PNG with data in front
    def testDataPrependedToPNG(self):
        '''Test a single PNG with data prepended'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test-prepend-random-data.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 6001452)

    # a test for the file being a single animated PNG with data in front
    def testDataPrependedToAPNG(self):
        '''Test a single PNG with data appended'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball-prepend-random-data.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 63435)
        self.assertIn('animated', testres['filesandlabels'][0][1])

    # a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndPNG(self):
        '''Test a single PNG with data cut from the end'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test-cut-data-from-end.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data cut from the end
    def testDataCutFromEndAPNG(self):
        '''Test a single animated PNG with data cut from the end'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-end.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data cut from the middle
    def testDataCutFromMiddlePNG(self):
        '''Test a single PNG with data cut from the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test-cut-data-from-middle.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data cut from the middle
    def testDataCutFromMiddleAPNG(self):
        '''Test a single animated PNG with data cut from the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-middle.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data added in the middle
    def testDataAddedInMiddlePNG(self):
        '''Test a single PNG with data added in the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test-data-added-to-middle.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data added in the middle
    def testDataAddedInMiddleAPNG(self):
        '''Test a single animated PNG with data added in the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball-data-added-to-middle.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data replaced in the middle
    def testDataReplacedInMiddlePNG(self):
        '''Test a single PNG with data replaced in the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'test-data-replaced-in-middle.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data replaced in the middle
    def testDataReplacedInMiddleAPNG(self):
        '''Test a single animated PNG with data replaced in the middle'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'png' / 'Animated_PNG_example_bouncing_beach_ball-data-replaced-in-middle.png'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackPNG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing JPEG files
class TestJPEG(TestBase):
    # a test for the file being a single JPEG
    def testFullfileIsJPEG(self):
        '''Test a single JPEG'''
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test.jpg'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single JPEG with data appended to it
    def testDataAppendedToJPEG(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test-add-random-data.jpg'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4676767)

    # a test for the file being a single JPEG with data in front
    def testDataPrependedToJPEG(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test-prepend-random-data.jpg'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4676767)

    # a test for the file being a single JPEG with data cut from the end
    def testDataCutFromEndJPEG(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test-cut-data-from-end.jpg'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data cut from the middle
    def testDataCutFromMiddleJPEG(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test-cut-data-from-middle.jpg'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data added in the middle
    def testDataAddedInMiddleJPEG(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test-data-added-to-middle.jpg'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data replaced in the middle
    def testDataReplacedInMiddleJPEG(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jpeg' / 'test-data-replaced-in-middle.jpg'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackJPEG(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing BMP files
class TestBMP(TestBase):
    # a test for the file being a single BMP
    def testFullfileIsBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test.bmp'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single BMP with data appended to it
    def testDataAppendedToBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test-add-random-data.bmp'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572666)

    # a test for the file being a single BMP with data in front
    def testDataPrependedToBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test-prepend-random-data.bmp'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572666)

    # a test for the file being a single BMP with data cut from the end
    def testDataCutFromEndBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test-cut-data-from-end.bmp'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data cut from the middle
    def testDataCutFromMiddleBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test-cut-data-from-middle.bmp'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data added in the middle
    def testDataAddedInMiddleBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test-data-added-to-middle.bmp'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data replaced in the middle
    def testDataReplacedInMiddleBMP(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bmp' / 'test-data-replaced-in-middle.bmp'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackBMP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing SGI files
class TestSGI(TestBase):
    # a test for the file being a single SGI
    def testFullfileIsSGI(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test.sgi'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single SGI
    def testFullfileIsSGIVerbatim(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim.sgi'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGI(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-add-random-data.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592418)

    # a test for the file being a single SGI with data appended to it
    def testDataAppendedToSGIVerbatim(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim-add-random-data.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572048)

    # a test for the file being a single SGI with data in front
    def testDataPrependedToSGI(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-prepend-random-data.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592418)

    # a test for the file being a single SGI with data in front
    def testDataPrependedToSGIVerbatim(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim-prepend-random-data.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572048)

    # a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGI(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-cut-data-from-end.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the end
    def testDataCutFromEndSGIVerbatim(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim-cut-data-from-end.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGI(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-cut-data-from-middle.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the middle
    def testDataCutFromMiddleSGIVerbatim(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim-cut-data-from-middle.sgi'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGI(self):
    #    filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-data-added-to-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data added in the middle
    #def testDataAddedInMiddleSGIVerbatim(self):
    #    filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim-data-added-to-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGI(self):
    #    filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-data-replaced-in-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data replaced in the middle
    #def testDataReplacedInMiddleSGIVerbatim(self):
    #    filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'sgi' / 'test-verbatim-data-replaced-in-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(fileresult, self.scan_environment, offset, self.unpackdir)
    #    self.assertFalse(testres['status'])


# a test class for testing Android sparse files
class TestAndroidSparse(TestBase):
    # a test for the file being a single Android sparse image
    def testFullfileIsAndroidSparse(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'simg' / 'zero.img'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangandroid.unpackAndroidSparse(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)


# a test class for testing SREC files
class TestSREC(TestBase):

    def testSRECWrong(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'srec' / 'srec-wrong.txt'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackSREC(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing GZIP files
class TestGZIP(TestBase):
    # a test for the file being a single gzip
    def testFullfileIsGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg.gz'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single gzip with data appended to it
    def testDataAppendedToGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg-add-random-data.gz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665601)

    # a test for the file being a single gzip with data in front
    def testDataPrependedToGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg-prepend-random-data.gz'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665601)

    # a test for the file being a single gzip with data cut from the end
    def testDataCutFromEndGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg-cut-data-from-end.gz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data cut from the middle
    def testDataCutFromMiddleGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg-cut-data-from-middle.gz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data added in the middle
    def testDataAddedInMiddleGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg-data-added-to-middle.gz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data replaced in the middle
    def testDataReplacedInMiddleGzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'gzip' / 'test.jpg-data-replaced-in-middle.gz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackGzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing ZIP files
class TestZIP(TestBase):
    # a test for the file being a single ZIP
    def testFullfileIsZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test.zip'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single ZIP with data appended to it
    def testDataAppendedToZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test-add-random-data.zip'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665740)

    # a test for the file being a single ZIP with data in front
    def testDataPrependedToZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test-prepend-random-data.zip'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665740)

    # a test for the file being a single ZIP with data cut from the end
    def testDataCutFromEndZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test-cut-data-from-end.zip'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data cut from the middle
    def testDataCutFromMiddleZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test-cut-data-from-middle.zip'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data added in the middle
    def testDataAddedInMiddleZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test-data-added-to-middle.zip'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data replaced in the middle
    def testDataReplacedInMiddleZip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zip' / 'test-data-replaced-in-middle.zip'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing LZ4 files
class TestLZ4(TestBase):

    # a test for the file being a single LZ4
    def testFullfileIsLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt.lz4'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single LZ4 with data appended to it
    def testDataAppendedToLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt-add-random-data.lz4'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 755644)

    # a test for the file being a single LZ4 with data in front
    def testDataPrependedToLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt-prepend-random-data.lz4'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 755644)

    # a test for the file being a single LZ4 with data cut from the end
    def testDataCutFromEndLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt-cut-data-from-end.lz4'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data cut from the middle
    def testDataCutFromMiddleLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt-cut-data-from-middle.lz4'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data added in the middle
    def testDataAddedInMiddleLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt-data-added-to-middle.lz4'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data replaced in the middle
    def testDataReplacedInMiddleLZ4(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lz4' / 'pg6130.txt-data-replaced-in-middle.lz4'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZ4(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing CPIO files
class TestCPIO(TestBase):

    # a test for the file being a single CPIO
    def testFullfileIsCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin.cpio'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def testFullfileIsCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old.cpio'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def testFullfileIsCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new.cpio'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def testFullfileIsCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc.cpio'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin-add-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-add-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new-add-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def testDataAppendedToCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc-add-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin-prepend-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-prepend-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new-prepend-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def testDataPrependedToCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc-prepend-random-data.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin-cut-data-from-end.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-cut-data-from-end.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new-cut-data-from-end.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def testDataCutFromEndCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc-cut-data-from-end.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin-cut-data-from-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-cut-data-from-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new-cut-data-from-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def testDataCutFromMiddleCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc-cut-data-from-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin-data-added-to-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-data-added-to-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new-data-added-to-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def testDataAddedInMiddleCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc-data-added-to-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOBin(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-bin-data-replaced-in-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOOld(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-old-data-replaced-in-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIONew(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-new-data-replaced-in-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def testDataReplacedInMiddleCPIOCRC(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'cpio' / 'test-crc-data-replaced-in-middle.cpio'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackCpio(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing XZ files
class TestXZ(TestBase):

    # a test for the file being a single XZ
    def testFullfileIsXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test.xz'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single XZ with data appended to it
    def testDataAppendedToXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test-add-random-data.xz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510744)

    # a test for the file being a single XZ with data in front
    def testDataPrependedToXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test-prepend-random-data.xz'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510744)

    # a test for the file being a single XZ with data cut from the end
    def testDataCutFromEndXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test-cut-data-from-end.xz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data cut from the middle
    def testDataCutFromMiddleXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test-cut-data-from-middle.xz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data added in the middle
    def testDataAddedInMiddleXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test-data-added-to-middle.xz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data replaced in the middle
    def testDataReplacedInMiddleXZ(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xz' / 'test-data-replaced-in-middle.xz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXZ(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing LZMA files
class TestLZMA(TestBase):

    # a test for the file being a single LZMA
    def testFullfileIsLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test.lzma'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single LZMA with data appended to it
    def testDataAppendedToLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test-add-random-data.lzma'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510623)

    # a test for the file being a single LZMA with data in front
    def testDataPrependedToLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test-prepend-random-data.lzma'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510623)

    # a test for the file being a single LZMA with data cut from the end
    def testDataCutFromEndLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test-cut-data-from-end.lzma'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data cut from the middle
    def testDataCutFromMiddleLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test-cut-data-from-middle.lzma'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data added in the middle
    def testDataAddedInMiddleLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test-data-added-to-middle.lzma'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data replaced in the middle
    def testDataReplacedInMiddleLZMA(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzma' / 'test-data-replaced-in-middle.lzma'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZMA(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing bzip2 files
class TestBzip2(TestBase):

    # a test for the file being a single bzip2
    def testFullfileIsBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test.bz2'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single bzip2 with data appended to it
    def testDataAppendedToBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test-add-random-data.bz2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530237)

    # a test for the file being a single bzip2 with data in front
    def testDataPrependedToBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test-prepend-random-data.bz2'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530237)

    # a test for the file being a single bzip2 with data cut from the end
    def testDataCutFromEndBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test-cut-data-from-end.bz2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data cut from the middle
    def testDataCutFromMiddleBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test-cut-data-from-middle.bz2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data added in the middle
    def testDataAddedInMiddleBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test-data-added-to-middle.bz2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data replaced in the middle
    def testDataReplacedInMiddleBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'bz2' / 'test-data-replaced-in-middle.bz2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackBzip2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing lzip files
class TestLzip(TestBase):

    # a test for the file being a single lzip
    def testFullfileIsLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test.lz'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single lzip with data appended to it
    def testDataAppendedToLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test-add-random-data.lz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511095)

    # a test for the file being a single lzip with data in front
    def testDataPrependedToLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test-prepend-random-data.lz'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511095)

    # a test for the file being a single lzip with data cut from the end
    def testDataCutFromEndLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test-cut-data-from-end.lz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data cut from the middle
    def testDataCutFromMiddleLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test-cut-data-from-middle.lz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data added in the middle
    def testDataAddedInMiddleLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test-data-added-to-middle.lz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data replaced in the middle
    def testDataReplacedInMiddleLzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzip' / 'test-data-replaced-in-middle.lz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing lzop files
class TestLzop(TestBase):

    # a test for the file being a single lzop
    def testFullfileIsLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test.lzo'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single lzop with data appended to it
    def testDataAppendedToLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test-add-random-data.lzo'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 588927)

    # a test for the file being a single lzop with data in front
    def testDataPrependedToLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test-prepend-random-data.lzo'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 588927)

    # a test for the file being a single lzop with data cut from the end
    def testDataCutFromEndLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test-cut-data-from-end.lzo'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzop with data cut from the middle
    def testDataCutFromMiddleLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test-cut-data-from-middle.lzo'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzop with data added in the middle
    def testDataAddedInMiddleLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test-data-added-to-middle.lzo'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzop with data replaced in the middle
    def testDataReplacedInMiddleLzop(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'lzop' / 'test-data-replaced-in-middle.lzo'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackLZOP(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing zstd files
class TestZstd(TestBase):

    # a test for the file being a single zstd
    def testFullfileIsZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test.zst'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single zstd with data appended to it
    def testDataAppendedToZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test-add-random-data.zst'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 583703)

    # a test for the file being a single zstd with data in front
    def testDataPrependedToZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test-prepend-random-data.zst'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 583703)

    # a test for the file being a single zstd with data cut from the end
    def testDataCutFromEndZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test-cut-data-from-end.zst'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data cut from the middle
    def testDataCutFromMiddleZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test-cut-data-from-middle.zst'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data added in the middle
    def testDataAddedInMiddleZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test-data-added-to-middle.zst'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data replaced in the middle
    def testDataReplacedInMiddleZstd(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'zstd' / 'test-data-replaced-in-middle.zst'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackZstd(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing 7z files
class Test7z(TestBase):

    # a test for the file being a single 7z
    def testFullfileIs7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test.7z'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single 7z with data appended to it
    def testDataAppendedTo7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test-add-random-data.7z'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511498)

    # a test for the file being a single 7z with data in front
    def testDataPrependedTo7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test-prepend-random-data.7z'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511498)

    # a test for the file being a single 7z with data cut from the end
    def testDataCutFromEnd7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test-cut-data-from-end.7z'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data cut from the middle
    def testDataCutFromMiddle7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test-cut-data-from-middle.7z'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data added in the middle
    def testDataAddedInMiddle7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test-data-added-to-middle.7z'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data replaced in the middle
    def testDataReplacedInMiddle7z(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / '7z' / 'test-data-replaced-in-middle.7z'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpack7z(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing ar files
class TestAr(TestBase):

    # a test for the file being a single ar
    def testFullfileIsAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test.ar'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single ar with data appended to it
    def testDataAppendedToAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test-add-random-data.ar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)

        # ar unpacker only works on complete files
        self.assertFalse(testres['status'])
        #self.assertTrue(testres['status'])
        #self.assertEqual(testres['length'], 511498)

    # a test for the file being a single ar with data in front
    def testDataPrependedToAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test-prepend-random-data.ar'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)

        # ar unpacker only works on complete files
        self.assertFalse(testres['status'])
        #self.assertTrue(testres['status'])
        #self.assertEqual(testres['length'], 511498)

    # a test for the file being a single ar with data cut from the end
    def testDataCutFromEndAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test-cut-data-from-end.ar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data cut from the middle
    def testDataCutFromMiddleAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test-cut-data-from-middle.ar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data added in the middle
    def testDataAddedInMiddleAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test-data-added-to-middle.ar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data replaced in the middle
    def testDataReplacedInMiddleAr(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'ar' / 'test-data-replaced-in-middle.ar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackAr(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing XAR files
class TestXAR(TestBase):

    # a test for the file being a single xar
    def testFullfileIsXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip.xar'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single xar
    def testFullfileIsXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2.xar'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single xar
    def testFullfileIsXARNone(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none.xar'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single xar with data appended to it
    def testDataAppendedToXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip-add-random-data.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 582324)

    # a test for the file being a single xar with data appended to it
    def testDataAppendedToXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2-add-random-data.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530707)

    # a test for the file being a single xar with data appended to it
    def testDataAppendedToXARNone(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none-add-random-data.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592861)

    # a test for the file being a single xar with data in front
    def testDataPrependedToXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip-prepend-random-data.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 582324)

    # a test for the file being a single xar with data in front
    def testDataPrependedToXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2-prepend-random-data.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530707)

    # a test for the file being a single xar with data in front
    def testDataPrependedToXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none-prepend-random-data.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592861)

    # a test for the file being a single xar with data cut from the end
    def testDataCutFromEndXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip-cut-data-from-end.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the end
    def testDataCutFromEndXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2-cut-data-from-end.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the end
    def testDataCutFromEndXARNone(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none-cut-data-from-end.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def testDataCutFromMiddleXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip-cut-data-from-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def testDataCutFromMiddleXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2-cut-data-from-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def testDataCutFromMiddleXARNone(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none-cut-data-from-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def testDataAddedInMiddleXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip-data-added-to-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def testDataAddedInMiddleXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2-data-added-to-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def testDataAddedInMiddleXARNone(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none-data-added-to-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def testDataReplacedInMiddleXAR(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-gzip-data-replaced-in-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def testDataReplacedInMiddleXARBzip2(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-bzip2-data-replaced-in-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def testDataReplacedInMiddleXARNone(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'xar' / 'test-none-data-replaced-in-middle.xar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackXAR(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing squashfs files
class TestSquashfs(TestBase):

    # a test for the file being a single squashfs
    def testFullfileIsSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test.sqsh'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single squashfs with data appended to it
    def testDataAppendedToSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test-add-random-data.sqsh'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 577536)

    # a test for the file being a single squashfs with data in front
    def testDataPrependedToSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test-prepend-random-data.sqsh'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 577536)

    # a test for the file being a single squashfs with data cut from the end
    def testDataCutFromEndSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test-cut-data-from-end.sqsh'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs with data cut from the middle
    def testDataCutFromMiddleSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test-cut-data-from-middle.sqsh'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs with data added in the middle
    def testDataAddedInMiddleSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test-data-added-to-middle.sqsh'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs
    # with data replaced in the middle
    def testDataReplacedInMiddleSquashfs(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'squashfs' / 'test-data-replaced-in-middle.sqsh'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackSquashfs(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing snappy files
class TestSnappy(TestBase):

    # a test for the file being a single snappy
    def testFullfileIsSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test.sz'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single snappy with data appended to it
    def testDataAppendedToSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test-add-random-data.sz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592508)

    # a test for the file being a single snappy with data in front
    def testDataPrependedToSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test-prepend-random-data.sz'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592508)

    # a test for the file being a single snappy with data cut from the end
    def testDataCutFromEndSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test-cut-data-from-end.sz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy with data cut from the middle
    def testDataCutFromMiddleSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test-cut-data-from-middle.sz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy with data added in the middle
    def testDataAddedInMiddleSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test-data-added-to-middle.sz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy
    # with data replaced in the middle
    def testDataReplacedInMiddleSnappy(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'snappy' / 'test-data-replaced-in-middle.sz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackSnappy(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing ISO files
class TestISO9660(TestBase):

    # a test for the file being a single iso9660
    def testFullfileIsISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test.iso'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single iso9660 with data appended to it
    def testDataAppendedToISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test-add-random-data.iso'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 952320)

    # a test for the file being a single iso9660 with data in front
    def testDataPrependedToISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test-prepend-random-data.iso'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 952320)

    # a test for the file being a single iso9660 with data cut from the end
    def testDataCutFromEndISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test-cut-data-from-end.iso'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660 with data cut from the middle
    def testDataCutFromMiddleISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test-cut-data-from-middle.iso'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660 with data added in the middle
    def testDataAddedInMiddleISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test-data-added-to-middle.iso'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660
    # with data replaced in the middle
    def testDataReplacedInMiddleISO9660(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'iso9660' / 'test-data-replaced-in-middle.iso'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackISO9660(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing tar files
class TestTar(TestBase):

    # a test for the file being a single tar
    def testFullfileIsTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test.tar'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single tar with absolute paths
    def testFullfileIsTarAbsolute(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'tar-abs.tar'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single tar with data appended to it
    def testDataAppendedToTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-add-random-data.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 604160)

    # a test for the file being a single tar with data in front
    def testDataPrependedToTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-prepend-random-data.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 604160)

    # a test for the file being a single tar with data cut from the end
    def testDataCutFromEndTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-cut-data-from-end.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data cut from the middle
    def testDataCutFromMiddleTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-cut-data-from-middle.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data added in the middle
    def testDataAddedInMiddleTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-data-added-to-middle.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data replaced in the middle
    def testDataReplacedInMiddleTar(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-data-replaced-in-middle.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with just directories
    def testFullfileIsTarDir(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'tar' / 'test-dir.tar'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackTar(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 10240)


# a test class for testing jffs2 files
class TestJFFS2(TestBase):

    # a test for the file being a single jffs2
    def testFullfileIsJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little.jffs2'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single jffs2
    def testFullfileIsJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big.jffs2'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single jffs2 with data appended to it
    def testDataAppendedToJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little-add-random-data.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data appended to it
    def testDataAppendedToJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big-add-random-data.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data in front
    def testDataPrependedToJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little-prepend-random-data.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data in front
    def testDataPrependedToJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big-prepend-random-data.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data cut from the end
    def testDataCutFromEndJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little-cut-data-from-end.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the end
    def testDataCutFromEndJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big-cut-data-from-end.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the middle
    def testDataCutFromMiddleJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little-cut-data-from-middle.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the middle
    def testDataCutFromMiddleJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big-cut-data-from-middle.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data added in the middle
    def testDataAddedInMiddleJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little-data-added-to-middle.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data added in the middle
    def testDataAddedInMiddleJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big-data-added-to-middle.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data replaced in the middle
    def testDataReplacedInMiddleJFFS2Little(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-little-data-replaced-in-middle.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data replaced in the middle
    def testDataReplacedInMiddleJFFS2Big(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'jffs2' / 'test-big-data-replaced-in-middle.jffs2'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangfilesystems.unpackJFFS2(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])


# a test class for testing rzip files
class TestRzip(TestBase):
    # a test for the file being a single rzip
    def testFullfileIsRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test.rz'
        fileresult = create_fileresult_for_path(filename)
        filesize = fileresult.filesize
        offset = 0
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single rzip with data appended to it
    def testDataAppendedToRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test-add-random-data.rz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530499)

    # a test for the file being a single rzip with data in front
    def testDataPrependedToRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test-prepend-random-data.rz'
        fileresult = create_fileresult_for_path(filename)
        offset = 128
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530499)

    # a test for the file being a single rzip with data cut from the end
    def testDataCutFromEndRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test-cut-data-from-end.rz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data cut from the middle
    def testDataCutFromMiddleRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test-cut-data-from-middle.rz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data added in the middle
    def testDataAddedInMiddleRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test-data-added-to-middle.rz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data replaced in the middle
    def testDataReplacedInMiddleRzip(self):
        filename = pathlib.Path(self.testdata_dir) / 'unpackers' / 'rzip' / 'test-data-replaced-in-middle.rz'
        fileresult = create_fileresult_for_path(filename)
        offset = 0
        testres = bangunpack.unpackRzip(fileresult, self.scan_environment, offset, self.unpackdir)
        self.assertFalse(testres['status'])

if __name__ == '__main__':
    unittest.main()
