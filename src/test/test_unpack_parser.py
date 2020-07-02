import pytest

from .util import *
from UnpackParserException import UnpackParserException
from UnpackParser import UnpackParser
from bangsignatures import get_unpackers
from parsers.database.sqlite.UnpackParser import SqliteUnpackParser
from parsers.image.gif.UnpackParser import GifUnpackParser

class InvalidUnpackParser(UnpackParser):
    pass

def test_unpack_parser_without_parse_method():
    p = InvalidUnpackParser(None, None, None, 0)
    with pytest.raises(UnpackParserException, match = r"undefined parse method") as cm:
        p.parse()

def test_unpackparser_list_has_derived_classes_only():
    assert UnpackParser not in get_unpackers()

def test_all_unpack_parsers_have_attributes():
    for unpackparser in get_unpackers():
        assert unpackparser.pretty_name is not None
        assert unpackparser.extensions is not None
        assert unpackparser.signatures is not None
        # assert all signatures are bytestrings
        i = 0
        for s_offset, s_text in unpackparser.signatures:
            assert type(s_text) == type(b'')

def test_unpackparsers_are_found():
    unpacker_names = [ u.__name__ for u in get_unpackers() ]
    assert 'GifUnpackParser' in unpacker_names
    assert 'VfatUnpackParser' in unpacker_names

def test_wrapped_unpackparser_raises_exception(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = SqliteUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException, match = r".*") as cm:
        r = p.parse_and_unpack()
    p.close()


def test_unpackparser_raises_exception(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GifUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException, match = r".*") as cm:
        r = p.parse_and_unpack()
    p.close()


def test_all_unpack_parsers_raise_exception_on_empty_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'empty'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    for unpackparser in get_unpackers():
        up = unpackparser(fr, scan_environment, data_unpack_dir, 0)
        up.open()
        # with pytest.raises(UnpackParserException, match = r".*", msg=unpackparser.__name__) as cm:
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = up.parse_and_unpack()
            pytest.fail("%s accepts empty file" % unpackparser.__name__)
        up.close()

