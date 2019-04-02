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

# load own modules
import bangunpack
import bangfilesystems
import bangmedia

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
    def test_fullfile(self):
        '''Test a single GIF'''
        filename = basetestdir / 'gif' / 'test.gif'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single GIF with data appended to it
    def test_appended(self):
        '''Test a single GIF with data appended'''
        filename = basetestdir / 'gif' / 'test-add-random-data.gif'
        offset = 0
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 7073713)

    # a test for the file being a single GIF with data in front
    def test_prepended(self):
        '''Test a single GIF with data prepended'''
        filename = basetestdir / 'gif' / 'test-prepend-random-data.gif'
        offset = 128
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 7073713)

    # a test for the file being a single GIF with data cut from the end
    def test_cut_from_end(self):
        '''Test a single GIF with data cut from the end'''
        filename = basetestdir / 'gif' / 'test-cut-data-from-end.gif'
        offset = 0
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data cut from the middle
    def test_cut_from_middle(self):
        '''Test a single GIF with data cut from the middle'''
        filename = basetestdir / 'gif' / 'test-cut-data-from-middle.gif'
        offset = 0
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data added in the middle
    def test_added_in_middle(self):
        '''Test a single GIF with data added in the middle'''
        filename = basetestdir / 'gif' / 'test-data-added-to-middle.gif'
        offset = 0
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single GIF with data replaced in the middle
    def test_replaced_in_middle(self):
        '''Test a single GIF with data replaced in the middle'''
        filename = basetestdir / 'gif' / 'test-data-replaced-in-middle.gif'
        offset = 0
        testres = bangmedia.unpackGIF(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        '''Test a single PNG'''
        filename = basetestdir / 'png' / 'test.png'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single animated PNG
    def test_fullfile_APNG(self):
        '''Test a single animated PNG'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball.png'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)
        self.assertIn('animated', testres['labels'])

    # a test for the file being a single PNG with data appended to it
    def test_appended(self):
        '''Test a single PNG with data appended'''
        filename = basetestdir / 'png' / 'test-add-random-data.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 6001452)

    # a test for the file being a single animated PNG with data appended to it
    def test_appended_APNG(self):
        '''Test a single animated PNG with data appended'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-add-random-data.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 63435)
        self.assertIn('animated', testres['filesandlabels'][0][1])

    # a test for the file being a single PNG with data in front
    def test_prepended(self):
        '''Test a single PNG with data prepended'''
        filename = basetestdir / 'png' / 'test-prepend-random-data.png'
        offset = 128
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 6001452)

    # a test for the file being a single animated PNG with data in front
    def test_prepended_APNG(self):
        '''Test a single PNG with data appended'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-prepend-random-data.png'
        offset = 128
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 63435)
        self.assertIn('animated', testres['filesandlabels'][0][1])

    # a test for the file being a single PNG with data cut from the end
    def test_cut_from_end(self):
        '''Test a single PNG with data cut from the end'''
        filename = basetestdir / 'png' / 'test-cut-data-from-end.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data cut from the end
    def test_cut_from_end_APNG(self):
        '''Test a single animated PNG with data cut from the end'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-end.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data cut from the middle
    def test_cut_from_middle(self):
        '''Test a single PNG with data cut from the middle'''
        filename = basetestdir / 'png' / 'test-cut-data-from-middle.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data cut from the middle
    def test_cut_from_middle_APNG(self):
        '''Test a single animated PNG with data cut from the middle'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-cut-data-from-middle.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data added in the middle
    def test_added_in_middle(self):
        '''Test a single PNG with data added in the middle'''
        filename = basetestdir / 'png' / 'test-data-added-to-middle.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data added in the middle
    def test_added_in_middle_APNG(self):
        '''Test a single animated PNG with data added in the middle'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-data-added-to-middle.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single PNG with data replaced in the middle
    def test_replaced_in_middle(self):
        '''Test a single PNG with data replaced in the middle'''
        filename = basetestdir / 'png' / 'test-data-replaced-in-middle.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single animated PNG
    # with data replaced in the middle
    def test_replaced_in_middle_APNG(self):
        '''Test a single animated PNG with data replaced in the middle'''
        filename = basetestdir / 'png' / 'Animated_PNG_example_bouncing_beach_ball-data-replaced-in-middle.png'
        offset = 0
        testres = bangmedia.unpackPNG(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        '''Test a single JPEG'''
        filename = basetestdir / 'jpeg' / 'test.jpg'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single JPEG with data appended to it
    def test_appended(self):
        filename = basetestdir / 'jpeg' / 'test-add-random-data.jpg'
        offset = 0
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4676767)

    # a test for the file being a single JPEG with data in front
    def test_prepended(self):
        filename = basetestdir / 'jpeg' / 'test-prepend-random-data.jpg'
        offset = 128
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4676767)

    # a test for the file being a single JPEG with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'jpeg' / 'test-cut-data-from-end.jpg'
        offset = 0
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'jpeg' / 'test-cut-data-from-middle.jpg'
        offset = 0
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'jpeg' / 'test-data-added-to-middle.jpg'
        offset = 0
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single JPEG with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'jpeg' / 'test-data-replaced-in-middle.jpg'
        offset = 0
        testres = bangmedia.unpackJPEG(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        filename = basetestdir / 'bmp' / 'test.bmp'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single BMP with data appended to it
    def test_appended(self):
        filename = basetestdir / 'bmp' / 'test-add-random-data.bmp'
        offset = 0
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572666)

    # a test for the file being a single BMP with data in front
    def test_prepended(self):
        filename = basetestdir / 'bmp' / 'test-prepend-random-data.bmp'
        offset = 128
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572666)

    # a test for the file being a single BMP with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'bmp' / 'test-cut-data-from-end.bmp'
        offset = 0
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data cut from the middle
    def test_Cut_from_middle(self):
        filename = basetestdir / 'bmp' / 'test-cut-data-from-middle.bmp'
        offset = 0
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'bmp' / 'test-data-added-to-middle.bmp'
        offset = 0
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single BMP with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'bmp' / 'test-data-replaced-in-middle.bmp'
        offset = 0
        testres = bangmedia.unpackBMP(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        filename = basetestdir / 'sgi' / 'test.sgi'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single SGI
    def test_fullfile_verbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim.sgi'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single SGI with data appended to it
    def test_appended(self):
        filename = basetestdir / 'sgi' / 'test-add-random-data.sgi'
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592418)

    # a test for the file being a single SGI with data appended to it
    def test_appended_verbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-add-random-data.sgi'
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572048)

    # a test for the file being a single SGI with data in front
    def test_prepended(self):
        filename = basetestdir / 'sgi' / 'test-prepend-random-data.sgi'
        offset = 128
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592418)

    # a test for the file being a single SGI with data in front
    def test_prepended_verbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-prepend-random-data.sgi'
        offset = 128
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 572048)

    # a test for the file being a single SGI with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'sgi' / 'test-cut-data-from-end.sgi'
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the end
    def test_cut_from_end_verbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-cut-data-from-end.sgi'
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'sgi' / 'test-cut-data-from-middle.sgi'
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single SGI with data cut from the middle
    def test_cut_from_middle_verbatim(self):
        filename = basetestdir / 'sgi' / 'test-verbatim-cut-data-from-middle.sgi'
        offset = 0
        testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data added in the middle
    #def test_added_in_middle(self):
    #    filename = basetestdir / 'sgi' / 'test-data-added-to-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data added in the middle
    #def test_added_in_middle_verbatim(self):
    #    filename = basetestdir / 'sgi' / 'test-verbatim-data-added-to-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data replaced in the middle
    #def test_replaced_in_middle(self):
    #    filename = basetestdir / 'sgi' / 'test-data-replaced-in-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
    #    self.assertFalse(testres['status'])

    ## a test for the file being a single SGI with data replaced in the middle
    #def test_replaced_in_middle_verbatim(self):
    #    filename = basetestdir / 'sgi' / 'test-verbatim-data-replaced-in-middle.sgi'
    #    offset = 0
    #    testres = bangmedia.unpackSGI(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        filename = basetestdir / 'simg' / 'zero.img'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangandroid.unpackAndroidSparse(filename, offset, self.tempdir, None)
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
    def test_srec_wrong(self):
        filename = basetestdir / 'srec' / 'srec-wrong.txt'
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
    def test_fullfile(self):
        filename = basetestdir / 'gzip' / 'test.jpg.gz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single gzip with data appended to it
    def test_appended(self):
        filename = basetestdir / 'gzip' / 'test.jpg-add-random-data.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665601)

    # a test for the file being a single gzip with data in front
    def test_prepended(self):
        filename = basetestdir / 'gzip' / 'test.jpg-prepend-random-data.gz'
        offset = 128
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665601)

    # a test for the file being a single gzip with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'gzip' / 'test.jpg-cut-data-from-end.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'gzip' / 'test.jpg-cut-data-from-middle.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'gzip' / 'test.jpg-data-added-to-middle.gz'
        offset = 0
        testres = bangunpack.unpackGzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single gzip with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'zip' / 'test.zip'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single ZIP with data appended to it
    def test_appended(self):
        filename = basetestdir / 'zip' / 'test-add-random-data.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665740)

    # a test for the file being a single ZIP with data in front
    def test_prepended(self):
        filename = basetestdir / 'zip' / 'test-prepend-random-data.zip'
        offset = 128
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 4665740)

    # a test for the file being a single ZIP with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'zip' / 'test-cut-data-from-end.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'zip' / 'test-cut-data-from-middle.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'zip' / 'test-data-added-to-middle.zip'
        offset = 0
        testres = bangunpack.unpackZip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ZIP with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt.lz4'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single LZ4 with data appended to it
    def test_appended(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-add-random-data.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 755644)

    # a test for the file being a single LZ4 with data in front
    def test_prepended(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-prepend-random-data.lz4'
        offset = 128
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 755644)

    # a test for the file being a single LZ4 with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-cut-data-from-end.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-cut-data-from-middle.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'lz4' / 'pg6130.txt-data-added-to-middle.lz4'
        offset = 0
        testres = bangunpack.unpackLZ4(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZ4 with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def test_fullfile_old(self):
        filename = basetestdir / 'cpio' / 'test-old.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def test_fullfile_new(self):
        filename = basetestdir / 'cpio' / 'test-new.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO
    def test_fullfile_crc(self):
        filename = basetestdir / 'cpio' / 'test-crc.cpio'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single CPIO with data appended to it
    def test_appended_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-add-random-data.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def test_appended_old(self):
        filename = basetestdir / 'cpio' / 'test-old-add-random-data.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def test_appended_new(self):
        filename = basetestdir / 'cpio' / 'test-new-add-random-data.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data appended to it
    def test_appended_crc(self):
        filename = basetestdir / 'cpio' / 'test-crc-add-random-data.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def test_prepended_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-prepend-random-data.cpio'
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def test_prepended_old(self):
        filename = basetestdir / 'cpio' / 'test-old-prepend-random-data.cpio'
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def test_prepended_new(self):
        filename = basetestdir / 'cpio' / 'test-new-prepend-random-data.cpio'
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data in front
    def test_prepended_crc(self):
        filename = basetestdir / 'cpio' / 'test-crc-prepend-random-data.cpio'
        offset = 128
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592896)

    # a test for the file being a single CPIO with data cut from the end
    def test_cut_from_end_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def test_cut_from_end_old(self):
        filename = basetestdir / 'cpio' / 'test-old-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def test_cut_from_end_new(self):
        filename = basetestdir / 'cpio' / 'test-new-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the end
    def test_cut_from_end_crc(self):
        filename = basetestdir / 'cpio' / 'test-crc-cut-data-from-end.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def test_cut_from_middle_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def test_cut_from_middle_old(self):
        filename = basetestdir / 'cpio' / 'test-old-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def test_cut_from_middle_new(self):
        filename = basetestdir / 'cpio' / 'test-new-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data cut from the middle
    def test_cut_from_middle_crc(self):
        filename = basetestdir / 'cpio' / 'test-crc-cut-data-from-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def test_added_in_middle_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def test_added_in_middle_old(self):
        filename = basetestdir / 'cpio' / 'test-old-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def test_added_in_middle_new(self):
        filename = basetestdir / 'cpio' / 'test-new-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data added in the middle
    def test_added_in_middle_crc(self):
        filename = basetestdir / 'cpio' / 'test-crc-data-added-to-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def test_replaced_in_middle_bin(self):
        filename = basetestdir / 'cpio' / 'test-old-bin-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def test_replaced_in_middle_old(self):
        filename = basetestdir / 'cpio' / 'test-old-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def test_replaced_in_middle_new(self):
        filename = basetestdir / 'cpio' / 'test-new-data-replaced-in-middle.cpio'
        offset = 0
        testres = bangunpack.unpackCpio(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single CPIO with data replaced in the middle
    def test_replaced_in_middle_crc(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'xz' / 'test.xz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single XZ with data appended to it
    def test_appended(self):
        filename = basetestdir / 'xz' / 'test-add-random-data.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510744)

    # a test for the file being a single XZ with data in front
    def test_prepended(self):
        filename = basetestdir / 'xz' / 'test-prepend-random-data.xz'
        offset = 128
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510744)

    # a test for the file being a single XZ with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'xz' / 'test-cut-data-from-end.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'xz' / 'test-cut-data-from-middle.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'xz' / 'test-data-added-to-middle.xz'
        offset = 0
        testres = bangunpack.unpackXZ(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single XZ with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'lzma' / 'test.lzma'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single LZMA with data appended to it
    def test_appended(self):
        filename = basetestdir / 'lzma' / 'test-add-random-data.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510623)

    # a test for the file being a single LZMA with data in front
    def test_prepended(self):
        filename = basetestdir / 'lzma' / 'test-prepend-random-data.lzma'
        offset = 128
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 510623)

    # a test for the file being a single LZMA with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'lzma' / 'test-cut-data-from-end.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'lzma' / 'test-cut-data-from-middle.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'lzma' / 'test-data-added-to-middle.lzma'
        offset = 0
        testres = bangunpack.unpackLZMA(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single LZMA with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'bz2' / 'test.bz2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single bzip2 with data appended to it
    def test_appended(self):
        filename = basetestdir / 'bz2' / 'test-add-random-data.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530237)

    # a test for the file being a single bzip2 with data in front
    def test_prepended(self):
        filename = basetestdir / 'bz2' / 'test-prepend-random-data.bz2'
        offset = 128
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530237)

    # a test for the file being a single bzip2 with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'bz2' / 'test-cut-data-from-end.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'bz2' / 'test-cut-data-from-middle.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'bz2' / 'test-data-added-to-middle.bz2'
        offset = 0
        testres = bangunpack.unpackBzip2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single bzip2 with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'lzip' / 'test.lz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single lzip with data appended to it
    def test_appended(self):
        filename = basetestdir / 'lzip' / 'test-add-random-data.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511095)

    # a test for the file being a single lzip with data in front
    def test_prepended(self):
        filename = basetestdir / 'lzip' / 'test-prepend-random-data.lz'
        offset = 128
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511095)

    # a test for the file being a single lzip with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'lzip' / 'test-cut-data-from-end.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'lzip' / 'test-cut-data-from-middle.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'lzip' / 'test-data-added-to-middle.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzip with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'lzip' / 'test-data-replaced-in-middle.lz'
        offset = 0
        testres = bangunpack.unpackLzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])


# a test class for testing lzop files
class TestLzop(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.tempdir = tempfile.mkdtemp(dir=tmpdirectory)

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.tempdir)

    # now all the test cases.
    # a test for the file being a single lzop
    def test_fullfile(self):
        filename = basetestdir / 'lzop' / 'test.lzo'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single lzop with data appended to it
    def test_appended(self):
        filename = basetestdir / 'lzop' / 'test-add-random-data.lzo'
        offset = 0
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 588927)

    # a test for the file being a single lzop with data in front
    def test_prepended(self):
        filename = basetestdir / 'lzop' / 'test-prepend-random-data.lzo'
        offset = 128
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 588927)

    # a test for the file being a single lzop with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'lzop' / 'test-cut-data-from-end.lzo'
        offset = 0
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzop with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'lzop' / 'test-cut-data-from-middle.lzo'
        offset = 0
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzop with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'lzop' / 'test-data-added-to-middle.lzo'
        offset = 0
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single lzop with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'lzop' / 'test-data-replaced-in-middle.lzo'
        offset = 0
        testres = bangunpack.unpackLZOP(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        filename = basetestdir / 'zstd' / 'test.zst'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single zstd with data appended to it
    def test_appended(self):
        filename = basetestdir / 'zstd' / 'test-add-random-data.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 583703)

    # a test for the file being a single zstd with data in front
    def test_prepended(self):
        filename = basetestdir / 'zstd' / 'test-prepend-random-data.zst'
        offset = 128
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 583703)

    # a test for the file being a single zstd with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'zstd' / 'test-cut-data-from-end.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'zstd' / 'test-cut-data-from-middle.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'zstd' / 'test-data-added-to-middle.zst'
        offset = 0
        testres = bangunpack.unpackZstd(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single zstd with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / '7z' / 'test.7z'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single 7z with data appended to it
    def test_appended(self):
        filename = basetestdir / '7z' / 'test-add-random-data.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511498)

    # a test for the file being a single 7z with data in front
    def test_prepended(self):
        filename = basetestdir / '7z' / 'test-prepend-random-data.7z'
        offset = 128
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 511498)

    # a test for the file being a single 7z with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / '7z' / 'test-cut-data-from-end.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / '7z' / 'test-cut-data-from-middle.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / '7z' / 'test-data-added-to-middle.7z'
        offset = 0
        testres = bangunpack.unpack7z(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single 7z with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'ar' / 'test.ar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single ar with data appended to it
    def test_appended(self):
        filename = basetestdir / 'ar' / 'test-add-random-data.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)

        # ar unpacker only works on complete files
        self.assertFalse(testres['status'])
        #self.assertTrue(testres['status'])
        #self.assertEqual(testres['length'], 511498)

    # a test for the file being a single ar with data in front
    def test_prepended(self):
        filename = basetestdir / 'ar' / 'test-prepend-random-data.ar'
        offset = 128
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)

        # ar unpacker only works on complete files
        self.assertFalse(testres['status'])
        #self.assertTrue(testres['status'])
        #self.assertEqual(testres['length'], 511498)

    # a test for the file being a single ar with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'ar' / 'test-cut-data-from-end.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'ar' / 'test-cut-data-from-middle.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'ar' / 'test-data-added-to-middle.ar'
        offset = 0
        testres = bangunpack.unpackAr(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single ar with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'xar' / 'test-gzip.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single xar (bzip2)
    def test_fullfile_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # now all the test cases.
    # a test for the file being a single xar
    def test_fullfile_no_compression(self):
        filename = basetestdir / 'xar' / 'test-none.xar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single xar with data appended to it
    def test_appended(self):
        filename = basetestdir / 'xar' / 'test-gzip-add-random-data.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 582324)

    # a test for the file being a single xar with data appended to it
    def test_appended_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-add-random-data.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530707)

    # a test for the file being a single xar with data appended to it
    def test_appended_no_compression(self):
        filename = basetestdir / 'xar' / 'test-none-add-random-data.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592861)

    # a test for the file being a single xar with data in front
    def test_prepended(self):
        filename = basetestdir / 'xar' / 'test-gzip-prepend-random-data.xar'
        offset = 128
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 582324)

    # a test for the file being a single xar with data in front
    def test_prepended_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-prepend-random-data.xar'
        offset = 128
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530707)

    # a test for the file being a single xar with data in front
    def test_prepended_no_compression(self):
        filename = basetestdir / 'xar' / 'test-none-prepend-random-data.xar'
        offset = 128
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592861)

    # a test for the file being a single xar with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'xar' / 'test-gzip-cut-data-from-end.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the end
    def test_cut_from_end_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-cut-data-from-end.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the end
    def test_cut_from_end_no_compression(self):
        filename = basetestdir / 'xar' / 'test-none-cut-data-from-end.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'xar' / 'test-gzip-cut-data-from-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def test_cut_from_middle_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-cut-data-from-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data cut from the middle
    def test_cut_from_middle_no_compression(self):
        filename = basetestdir / 'xar' / 'test-none-cut-data-from-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'xar' / 'test-gzip-data-added-to-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def test_added_in_middle_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-data-added-to-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data added in the middle
    def test_added_in_middle_no_compression(self):
        filename = basetestdir / 'xar' / 'test-none-data-added-to-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'xar' / 'test-gzip-data-replaced-in-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def test_replaced_in_middle_bzip2(self):
        filename = basetestdir / 'xar' / 'test-bzip2-data-replaced-in-middle.xar'
        offset = 0
        testres = bangunpack.unpackXAR(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single xar with data replaced in the middle
    def test_replaced_in_middle_no_compression(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'squashfs' / 'test.sqsh'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single squashfs with data appended to it
    def test_appended(self):
        filename = basetestdir / 'squashfs' / 'test-add-random-data.sqsh'
        offset = 0
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 577536)

    # a test for the file being a single squashfs with data in front
    def test_prepended(self):
        filename = basetestdir / 'squashfs' / 'test-prepend-random-data.sqsh'
        offset = 128
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 577536)

    # a test for the file being a single squashfs with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'squashfs' / 'test-cut-data-from-end.sqsh'
        offset = 0
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'squashfs' / 'test-cut-data-from-middle.sqsh'
        offset = 0
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'squashfs' / 'test-data-added-to-middle.sqsh'
        offset = 0
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single squashfs
    # with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'squashfs' / 'test-data-replaced-in-middle.sqsh'
        offset = 0
        testres = bangfilesystems.unpackSquashfs(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        filename = basetestdir / 'snappy' / 'test.sz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single snappy with data appended to it
    def test_appended(self):
        filename = basetestdir / 'snappy' / 'test-add-random-data.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592508)

    # a test for the file being a single snappy with data in front
    def test_prepended(self):
        filename = basetestdir / 'snappy' / 'test-prepend-random-data.sz'
        offset = 128
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 592508)

    # a test for the file being a single snappy with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'snappy' / 'test-cut-data-from-end.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'snappy' / 'test-cut-data-from-middle.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'snappy' / 'test-data-added-to-middle.sz'
        offset = 0
        testres = bangunpack.unpackSnappy(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single snappy
    # with data replaced in the middle
    def test_replaced_in_middle(self):
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
    def test_fullfile(self):
        filename = basetestdir / 'iso9660' / 'test.iso'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single iso9660 with data appended to it
    def test_appended(self):
        filename = basetestdir / 'iso9660' / 'test-add-random-data.iso'
        offset = 0
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 952320)

    # a test for the file being a single iso9660 with data in front
    def test_prepended(self):
        filename = basetestdir / 'iso9660' / 'test-prepend-random-data.iso'
        offset = 128
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 952320)

    # a test for the file being a single iso9660 with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'iso9660' / 'test-cut-data-from-end.iso'
        offset = 0
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660 with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'iso9660' / 'test-cut-data-from-middle.iso'
        offset = 0
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660 with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'iso9660' / 'test-data-added-to-middle.iso'
        offset = 0
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single iso9660
    # with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'iso9660' / 'test-data-replaced-in-middle.iso'
        offset = 0
        testres = bangfilesystems.unpackISO9660(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        filename = basetestdir / 'tar' / 'test.tar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single tar with absolute paths
    def test_fullfile_absolute(self):
        filename = basetestdir / 'tar' / 'tar-abs.tar'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single tar with data appended to it
    def test_appended(self):
        filename = basetestdir / 'tar' / 'test-add-random-data.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 604160)

    # a test for the file being a single tar with data in front
    def test_prepended(self):
        filename = basetestdir / 'tar' / 'test-prepend-random-data.tar'
        offset = 128
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 604160)

    # a test for the file being a single tar with data cut from the end
    def test_cut_from_end(self):
        filename = basetestdir / 'tar' / 'test-cut-data-from-end.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data cut from the middle
    def test_cut_from_middle(self):
        filename = basetestdir / 'tar' / 'test-cut-data-from-middle.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data added in the middle
    def test_added_in_middle(self):
        filename = basetestdir / 'tar' / 'test-data-added-to-middle.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with data replaced in the middle
    def test_replaced_in_middle(self):
        filename = basetestdir / 'tar' / 'test-data-replaced-in-middle.tar'
        offset = 0
        testres = bangunpack.unpackTar(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single tar with just directories
    def test_fullfile_directories(self):
        filename = basetestdir / 'tar' / 'test-dir.tar'
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

    # now all the test cases for both little and big endian files
    # a test for the file being a single jffs2
    def test_fullfile_little(self):
        '''Test a JFFS2 file (little endian)'''
        filename = basetestdir / 'jffs2' / 'test-little.jffs2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single jffs2
    def test_fullfile_big(self):
        '''Test a JFFS2 file (big endian)'''
        filename = basetestdir / 'jffs2' / 'test-big.jffs2'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single jffs2 with data appended to it
    def test_appended_little(self):
        '''Test a JFFS2 file (little endian) with data appended'''
        filename = basetestdir / 'jffs2' / 'test-little-add-random-data.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data appended to it
    def test_appended_big(self):
        '''Test a JFFS2 file (big endian) with data appended'''
        filename = basetestdir / 'jffs2' / 'test-big-add-random-data.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data in front
    def test_prepended_to_little(self):
        '''Test a JFFS2 file (little endian) with data prepended'''
        filename = basetestdir / 'jffs2' / 'test-little-prepend-random-data.jffs2'
        offset = 128
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data in front
    def test_prepended_to_big(self):
        '''Test a JFFS2 file (big endian) with data prepended'''
        filename = basetestdir / 'jffs2' / 'test-big-prepend-random-data.jffs2'
        offset = 128
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 594192)

    # a test for the file being a single jffs2 with data cut from the end
    def test_cut_from_end_little(self):
        '''Test a JFFS2 file (little endian) with data cut from the end'''
        filename = basetestdir / 'jffs2' / 'test-little-cut-data-from-end.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the end
    def test_cut_from_end_big(self):
        '''Test a JFFS2 file (big endian) with data cut from the end'''
        filename = basetestdir / 'jffs2' / 'test-big-cut-data-from-end.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the middle
    def test_cut_from_middle_little(self):
        '''Test a JFFS2 file (little endian) with data cut from the middle'''
        filename = basetestdir / 'jffs2' / 'test-little-cut-data-from-middle.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data cut from the middle
    def test_cut_from_middle_big(self):
        '''Test a JFFS2 file (big endian) with data cut from the middle'''
        filename = basetestdir / 'jffs2' / 'test-big-cut-data-from-middle.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data added in the middle
    def test_added_in_middle_little(self):
        '''Test a JFFS2 file (little endian) with data added in the middle'''
        filename = basetestdir / 'jffs2' / 'test-little-data-added-to-middle.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data added in the middle
    def test_added_in_middle_big(self):
        '''Test a JFFS2 file (big endian) with data added in the middle'''
        filename = basetestdir / 'jffs2' / 'test-big-data-added-to-middle.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data replaced in the middle
    def test_replaced_in_middle_little(self):
        '''Test a JFFS2 file (little endian) with data replaced in the middle'''
        filename = basetestdir / 'jffs2' / 'test-little-data-replaced-in-middle.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single jffs2 with data replaced in the middle
    def test_replaced_in_middle_big(self):
        '''Test a JFFS2 file (big endian) with data replaced in the middle'''
        filename = basetestdir / 'jffs2' / 'test-big-data-replaced-in-middle.jffs2'
        offset = 0
        testres = bangfilesystems.unpackJFFS2(filename, offset, self.tempdir, None)
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
    def test_fullfile(self):
        '''Test a single RZIP file'''
        filename = basetestdir / 'rzip' / 'test.rz'
        filesize = filename.stat().st_size
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], filesize)

    # a test for the file being a single rzip with data appended to it
    def test_append(self):
        '''Test a single RZIP file with data appended'''
        filename = basetestdir / 'rzip' / 'test-add-random-data.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530499)

    # a test for the file being a single rzip with data in front
    def test_prepend(self):
        '''Test a single RZIP file with data prepended'''
        filename = basetestdir / 'rzip' / 'test-prepend-random-data.rz'
        offset = 128
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertTrue(testres['status'])
        self.assertEqual(testres['length'], 530499)

    # a test for the file being a single rzip with data cut from the end
    def test_cut_from_end(self):
        '''Test a single RZIP file with data cut from the end'''
        filename = basetestdir / 'rzip' / 'test-cut-data-from-end.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data cut from the middle
    def test_cut_from_middle(self):
        '''Test a single RZIP file with data cut from the middle'''
        filename = basetestdir / 'rzip' / 'test-cut-data-from-middle.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data added in the middle
    def test_added_in_middle(self):
        '''Test a single RZIP file with data added in the middle'''
        filename = basetestdir / 'rzip' / 'test-data-added-to-middle.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

    # a test for the file being a single rzip with data replaced in the middle
    def test_replaced_in_middle(self):
        '''Test a single RZIP file with data replaced in the middle'''
        filename = basetestdir / 'rzip' / 'test-data-replaced-in-middle.rz'
        offset = 0
        testres = bangunpack.unpackRzip(filename, offset, self.tempdir, None)
        self.assertFalse(testres['status'])

if __name__ == '__main__':
    unittest.main()
