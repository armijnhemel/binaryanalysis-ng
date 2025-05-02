import sys, os
from util import *
from mock_metadirectory import *

from bang.parsers.image.ico.UnpackParser import IcoUnpackParser

def test_load_standard_ico_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'ico' / 'test.ico'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = IcoUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert unpacked_md.unpacked_files == {}


