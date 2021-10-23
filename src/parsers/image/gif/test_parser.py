import sys, os
from test.util import *
from test.mock_metadirectory import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GifUnpackParser

def test_load_standard_gif_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gif' / 'test.gif'
    with testfile.open('rb') as f:
        p = GifUnpackParser(f, 0)
        p.parse()
        md = MockMetaDirectory()
        p.write_info(md)
        for _ in p.unpack(md): pass
        assert md.unpacked_files == {}
        assert md.info['metadata']['width'] == 3024

def test_load_png_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'png' / 'test.png'
    with testfile.open('rb') as f:
        p = GifUnpackParser(f, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            p.parse()

