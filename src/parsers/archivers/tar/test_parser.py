import sys, os
import pytest
from test.util import *
from test.mock_metadirectory import *
from UnpackParserException import UnpackParserException

from .UnpackParser import TarUnpackParser

def test_load_tar_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'tar'/ 'test.tar'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
    p = TarUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    extracted_fn = data_unpack_dir / 'test.sgi'
    assert r.get_unpacked_files()[0].filename == extracted_fn
    assert r.get_unpacked_files()[0].labels == set()


def test_load_absolute_tar_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'tar'/ 'tar-abs.tar'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
    p = TarUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    extracted_fn = "/tmp/test.sgi"
    assert r.get_unpacked_files()[0].filename == extracted_fn
    assert r.get_unpacked_files()[0].labels == set()
    # TODO: check where file is extracted


def test_invalid_file_not_tar(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'gif'/ 'test.gif'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
    p = TarUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException):
        r = p.parse_and_unpack()
    p.close()


