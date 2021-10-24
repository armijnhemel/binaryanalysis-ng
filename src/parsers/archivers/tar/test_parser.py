import sys, os
import pytest
from test.util import *
from test.mock_metadirectory import *
from UnpackParserException import UnpackParserException

from .UnpackParser import TarUnpackParser

def test_load_tar_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'tar'/ 'test.tar'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = TarUnpackParser(f, 0, sz)
        p.parse_from_offset()
        p.write_info(md)
        for _ in p.unpack(md): pass
    extracted_fn = md.unpacked_path(pathlib.Path('test.sgi'))
    assert extracted_fn in md.unpacked_files


def test_load_absolute_tar_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'tar'/ 'tar-abs.tar'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = TarUnpackParser(f, 0, sz)
        p.parse_from_offset()
        p.write_info(md)
        for _ in p.unpack(md): pass
    extracted_fn = md.unpacked_path(pathlib.Path('/tmp/test.sgi'))
    assert extracted_fn in md.unpacked_files

def test_invalid_file_not_tar(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gif'/ 'test.gif'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = TarUnpackParser(f, 0, sz)
        with pytest.raises(UnpackParserException):
            p.parse_from_offset()
            p.write_info(md)
            for _ in p.unpack(md): pass


