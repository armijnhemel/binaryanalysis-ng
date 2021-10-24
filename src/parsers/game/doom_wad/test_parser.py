import sys, os
from test.util import *
from test.mock_metadirectory import *

from UnpackParserException import UnpackParserException
from .UnpackParser import DoomWadUnpackParser

def test_load_standard_wad_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'download' / 'game' / 'doom_wad' / 'doom1.wad'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = DoomWadUnpackParser(f, 0, sz)
        p.parse_from_offset()
        md = MockMetaDirectory()
        p.write_info(md)
        for _ in p.unpack(md): pass
        assert md.unpacked_files == {}

def test_load_png_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'png' / 'test.png'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = DoomWadUnpackParser(f, 0, sz)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = p.parse_from_offset()


