import sys, os
from test.util import *
from test.mock_metadirectory import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GimpBrushUnpackParser

def test_load_standard_gbr_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gimpbrush' / 'test.gbr'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = GimpBrushUnpackParser(f, 0, sz)
        p.parse_from_offset()
        md = MockMetaDirectory()
        p.write_info(md)
        for _ in p.unpack(md): pass
        assert md.unpacked_files == {}
        assert md.info['metadata']['width'] == 64


def test_load_offset_gbr_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gimpbrush' / 'test-prepend-random-data.gbr'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = GimpBrushUnpackParser(f, 128, sz)
        p.parse_from_offset()
        md = MockMetaDirectory()
        p.write_info(md)
        for _ in p.unpack(md): pass
        assert md.unpacked_files == {}
        assert md.info['metadata']['width'] == 64

