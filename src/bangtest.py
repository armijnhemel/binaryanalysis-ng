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

    def testFullfileIsGIF(self):
        filename = os.path.join(basetestdir, 'gif', 'test.gif')
        filesize = os.stat(filename).st_size
        offset = 0
        testres = bangunpack.unpackGIF(filename, offset, self.tempdir, None)
        self.assertTrue(testres[0])
        self.assertEqual(testres[1], filesize)

if __name__ == '__main__':
    unittest.main()
