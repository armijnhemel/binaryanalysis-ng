import sys, os
from test.util import *
from test.mock_metadirectory import *

from .UnpackParser import IcoUnpackParser

def test_load_standard_ico_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'ico' / 'test.ico'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = IcoUnpackParser(f, 0, sz)
        p.parse_from_offset()
        md = MockMetaDirectory()
        p.write_info(md)
        for _ in p.unpack(md): pass
        assert md.unpacked_files == {}


