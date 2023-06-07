import sys, os
from util import *
from mock_metadirectory import *

from bang.UnpackParserException import UnpackParserException
from bang.parsers.media.wav.UnpackParser import WavUnpackParser

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

