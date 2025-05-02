import sys, os
from util import *
from mock_metadirectory import *

from bang.UnpackParserException import UnpackParserException
from bang.parsers.image.gimp_brush.UnpackParser import GimpBrushUnpackParser

def test_load_standard_gbr_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gimpbrush' / 'test.gbr'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GimpBrushUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert unpacked_md.unpacked_files == {}
        assert unpacked_md.info['metadata']['width'] == 64


def test_load_offset_gbr_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gimpbrush' / 'test-prepend-random-data.gbr'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GimpBrushUnpackParser(opened_md, 128)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert unpacked_md.unpacked_files == {}
        assert unpacked_md.info['metadata']['width'] == 64

