import sys, os
import pytest
from test.util import *

from .UnpackParser import RarUnpackParser

def test_load_standard_file(scan_environment):
    rel_testfile = pathlib.Path('a') / 'hachoir-core.rar'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = RarUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r['status']
    assert r['length'] == filesize
    assert r['filesandlabels'] == []

