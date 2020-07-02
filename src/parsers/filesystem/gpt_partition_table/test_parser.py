import sys, os
from test.util import *

from .UnpackParser import GptPartitionTableUnpackParser

def test_load_standard_file(scan_environment):
    rel_testfile = pathlib.Path('a') / 'OPNsense-18.1.6-OpenSSL-vga-amd64.img'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GptPartitionTableUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r['status']
    assert r['length'] == filesize
    assert len(r['filesandlabels']) == 4


