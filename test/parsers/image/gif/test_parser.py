import sys, os
from util import *

from bang.UnpackParserException import UnpackParserException
from bang.parsers.image.gif.UnpackParser import GifUnpackParser

def test_load_standard_gif_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gif' / 'test.gif'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GifUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert unpacked_md.unpacked_files == {}
        assert unpacked_md.info['metadata']['width'] == 3024

def test_load_png_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'png' / 'test.png'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GifUnpackParser(opened_md, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            p.parse_from_offset()
            p.write_info(opened_md)
            for _ in p.unpack(opened_md): pass

