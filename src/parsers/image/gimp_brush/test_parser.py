import sys, os
from test.util import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GimpBrushUnpackParser

def test_load_standard_gbr_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'gimpbrush' / 'test.gbr'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GimpBrushUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r['status']
    assert r['length'] == filesize
    assert r['filesandlabels'] == []
    assert r['metadata']['width'] == 64

