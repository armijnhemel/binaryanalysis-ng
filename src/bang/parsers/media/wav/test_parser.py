import sys, os
from test.util import *
from test.mock_metadirectory import *

from UnpackParserException import UnpackParserException
from .UnpackParser import WavUnpackParser

def test_load_standard_wav_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'wav' / 'test.wav'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = WavUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert unpacked_md.unpacked_files == {}

