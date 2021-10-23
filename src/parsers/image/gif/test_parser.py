import sys, os
from test.util import *
from test.mock_metadirectory import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GifUnpackParser

def test_load_standard_gif_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gif' / 'test.gif'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = GifUnpackParser(f, 0, sz)
        p.parse()
        md = MockMetaDirectory()
        p.write_info(md)
        for _ in p.unpack(md): pass
        assert md.unpacked_files == {}
        assert md.info['metadata']['width'] == 3024

def test_load_png_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'png' / 'test.png'
    sz = testfile.stat().st_size
    with testfile.open('rb') as f:
        p = GifUnpackParser(f, 0, sz)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            p.parse()

