from util import *
import unittest
import os
import sys
import pathlib

from bang.scan_environment import ScanEnvironment
from bang.UnpackParser import UnpackParser
from FileResult import FileResult

def test_create_unpackparser():
    up = create_unpackparser('FirstUnpacker', fail = False,
                extensions = ['.txt'],
                signatures = [ (0,b'ABCD'), (5,b'DCBA') ]
            )
    assert up.__name__ == 'FirstUnpacker'
    assert up.extensions == ['.txt']
    assert up.is_valid_extension is not None

def test_get_unpackparsers_from_scan_environment(scan_environment):
    unpackparsers = [
            create_unpackparser('FirstUnpacker', fail = False,
                extensions = ['.txt'],
                signatures = [ (0,b'ABCD'), (5,b'DCBA') ]
            ),
            create_unpackparser('SecondUnpacker', fail = False,
                extensions = ['.bin', '.hex'],
                signatures = [ (10,b'0000'), (10,b'1111') ]
            ),
            create_unpackparser('ThirdUnpacker', fail = True,
                extensions = ['.hex'],
                signatures = [ (0,b'ABCD') ]
            ),
            create_unpackparser('FourthUnpacker', fail = True,
                extensions = ['.hex'],
                signatures = [ (1,b'c0ffee')],
                scan_if_featureless = True
            ),
        ]
    scan_environment.parsers.unpackparsers = unpackparsers
    assert list(scan_environment.parsers.unpackparsers) == unpackparsers
    maxDiff = None
    assert scan_environment.parsers.unpackparsers_for_extensions == {
            ".txt": [ unpackparsers[0] ],
            ".bin": [ unpackparsers[1] ],
            ".hex": [ unpackparsers[1], unpackparsers[2], unpackparsers[3] ]
        }
    assert scan_environment.parsers.unpackparsers_for_signatures == {
            (0,b'ABCD'): [ unpackparsers[0], unpackparsers[2] ],
            (5,b'DCBA'): [ unpackparsers[0] ],
            (1,b'c0ffee'): [ unpackparsers[3] ],
            (10,b'0000'): [ unpackparsers[1] ],
            (10,b'1111'): [ unpackparsers[1] ]
        }
    assert scan_environment.parsers.unpackparsers_for_featureless_files == [ unpackparsers[3] ]


if __name__ == "__main__":
    unittest.main()
