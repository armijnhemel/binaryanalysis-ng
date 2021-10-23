import pytest

from .util import *
from UnpackParserException import UnpackParserException
from UnpackParser import UnpackParser
from bangsignatures import get_unpackers
from parsers.database.sqlite.UnpackParser import SqliteUnpackParser
from parsers.image.gif.UnpackParser import GifUnpackParser

class InvalidUnpackParser(UnpackParser):
    pass

@pytest.fixture(params = get_unpackers())
def unpackparser(request):
    return request.param

def test_unpack_parser_without_parse_method():
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    with testfile.open('rb') as f:
        p = InvalidUnpackParser(f, 0)
        with pytest.raises(UnpackParserException, match = r"undefined parse method") as cm:
            p.parse()

def test_unpackparser_list_has_derived_classes_only():
    assert UnpackParser not in get_unpackers()

def test_all_unpack_parsers_have_attributes(unpackparser):
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
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'

    with testfile.open('rb') as f:
        p = SqliteUnpackParser(f, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = p.parse()

def test_unpackparser_raises_exception(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    with testfile.open('rb') as f:
        p = GifUnpackParser(f, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = p.parse()

def test_all_unpack_parsers_raise_exception_on_empty_file(scan_environment, unpackparser):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'empty'
    with testfile.open('rb') as f:
        up = unpackparser(f, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = up.parse_and_unpack()
            pytest.fail("%s accepts empty file" % unpackparser.__name__)

