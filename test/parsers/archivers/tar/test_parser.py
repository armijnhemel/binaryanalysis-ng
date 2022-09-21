import sys, os
import pytest
from util import *
from mock_metadirectory import *
from bang.UnpackParserException import UnpackParserException

from bang.parsers.archivers.tar.UnpackParser import TarUnpackParser

def test_load_tar_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'tar'/ 'test.tar'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = TarUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        extracted_fn = unpacked_md.unpacked_path(pathlib.Path('test.sgi'))
        assert extracted_fn in unpacked_md.unpacked_files


def test_load_absolute_tar_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'tar'/ 'tar-abs.tar'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = TarUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        extracted_fn = unpacked_md.unpacked_path(pathlib.Path('/tmp/test.sgi'))
        assert extracted_fn in unpacked_md.unpacked_files

def test_invalid_file_not_tar(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'gif'/ 'test.gif'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = TarUnpackParser(opened_md, 0)
        with pytest.raises(UnpackParserException):
            p.parse_from_offset()
            p.write_info(opened_md)
            for _ in p.unpack(opened_md): pass


