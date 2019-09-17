# from TestUtil import *
import unittest
import os
import sys
import pathlib

from ScanEnvironment import ScanEnvironment
from UnpackParser import UnpackParser
from FileResult import FileResult

def parse_and_unpack_success(self):
    return {
            'status': True,
    }
    pass
    
def parse_and_unpack_fail(self):
    raise UnpackParserException("failing unpackparser")

def create_unpackparser(name, fail = False,
        extensions = [], signatures = [],
        pretty_name = '', scan_if_featureless = False): 
    if fail:
        parse_and_unpack_method = parse_and_unpack_fail
    else:
        parse_and_unpack_method = parse_and_unpack_success
    c = type(name, (UnpackParser,), {
                'extensions': extensions,
                'signatures': signatures,
                'scan_if_featureless': scan_if_featureless,
                'parse_and_unpack': parse_and_unpack_method
            })
    return c



class TestScanEnvironment(unittest.TestCase):
    def create_scan_environment(self,
                maxbytes = 0, readsize = 0, createbytecounter = False,
                createjson = False, runfilescans = False, tlshmaximum = 1024,
                synthesizedminimum = 200, logging = False,
                paddingname = 'PADDING', unpackdirectory = pathlib.Path('.'),
                temporarydirectory = pathlib.Path('.'),
                resultsdirectory = pathlib.Path('.'),
                scanfilequeue = None, resultqueue = None,
                processlock = None, checksumdict = None):
        return ScanEnvironment(maxbytes, readsize, createbytecounter,
                createjson, runfilescans, tlshmaximum, synthesizedminimum,
                logging, paddingname, unpackdirectory, temporarydirectory,
                 resultsdirectory, scanfilequeue, resultqueue, processlock,
                 checksumdict)

    # test get_unpack_path from fileresult
    # 1. from root fileresult, return path as is
    def test_unpack_path_for_relative_root_fileresult_is_path(self):
        se = self.create_scan_environment(unpackdirectory =
                pathlib.Path('/test'))
        path = pathlib.Path('a') / 'b'
        fr = FileResult(None, path, set())
        self.assertEqual(se.get_unpack_path_for_fileresult(fr), path)
    def test_unpack_path_for_absolute_root_fileresult_is_path(self):
        se = self.create_scan_environment(unpackdirectory =
                pathlib.Path('/test'))
        path = pathlib.Path('/a') / 'b'
        fr = FileResult(None, path, set())
        self.assertEqual(se.get_unpack_path_for_fileresult(fr), path)
    # 2. if fileresult has a parent, path must be in unpack directory
    def test_unpack_path_for_child_fileresult_is_in_unpack_directory(self):
        se = self.create_scan_environment(unpackdirectory =
                pathlib.Path('/test'))
        path = pathlib.Path('a') / 'b'
        frparent = FileResult(None, path.parent, set())
        fr = FileResult(frparent, path, set())
        self.assertEqual(se.get_unpack_path_for_fileresult(fr),
                pathlib.Path('/test') / path)

    def test_scanenvironment_get_unpack_path(self):
        se = self.create_scan_environment(unpackdirectory =
                pathlib.Path('/test'))
        self.assertEqual(se.unpack_path('a'), pathlib.Path('/test/a'))

    def test_create_unpackparser(self):
        up = create_unpackparser('FirstUnpacker', fail = False,
                    extensions = ['.txt'],
                    signatures = [ (0,'ABCD'), (5,'DCBA') ]
                )
        self.assertEqual(up.__name__,'FirstUnpacker')
        self.assertEqual(up.extensions, ['.txt'])
        self.assertIsNotNone(up.is_valid_extension)
 
    def test_get_unpackparsers_from_scan_environment(self):
        se = self.create_scan_environment(unpackdirectory =
                pathlib.Path('/test'))
        unpackparsers = [
                create_unpackparser('FirstUnpacker', fail = False,
                    extensions = ['.txt'],
                    signatures = [ (0,'ABCD'), (5,'DCBA') ]
                ),
                create_unpackparser('SecondUnpacker', fail = False,
                    extensions = ['.bin', '.hex'],
                    signatures = [ (10,'0000'), (10,'1111') ]
                ),
                create_unpackparser('ThirdUnpacker', fail = True,
                    extensions = ['.hex'],
                    signatures = [ (0,'ABCD') ]
                ),
                create_unpackparser('FourthUnpacker', fail = True,
                    extensions = ['.hex'],
                    signatures = [ (1,'c0ffee')],
                    scan_if_featureless = True
                ),
            ]
        for up in unpackparsers:
            se.add_unpackparser(up)
        self.assertEqual(se.get_unpackparsers(), unpackparsers)
        self.maxDiff = None
        self.assertEqual(se.get_unpackparsers_for_extensions(), {
                ".txt": [ unpackparsers[0] ],
                ".bin": [ unpackparsers[1] ],
                ".hex": [ unpackparsers[1], unpackparsers[2], unpackparsers[3] ]
            })
        self.assertEqual(se.get_unpackparsers_for_signatures(), {
                (0,'ABCD'): [ unpackparsers[0], unpackparsers[2] ],
                (5,'DCBA'): [ unpackparsers[0] ],
                (1,'c0ffee'): [ unpackparsers[3] ],
                (10,'0000'): [ unpackparsers[1] ],
                (10,'1111'): [ unpackparsers[1] ]
            })
        self.assertEqual(se.get_unpackparsers_for_featureless_files(),
                [ unpackparsers[3] ])



if __name__ == "__main__":
    unittest.main()
