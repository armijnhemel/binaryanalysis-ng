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

def test_unpack_parser_without_parse_method(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = InvalidUnpackParser(opened_md, 0)
        with pytest.raises(UnpackParserException, match = r"undefined parse method") as cm:
            p.parse_from_offset()

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
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = SqliteUnpackParser(opened_md, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = p.parse_from_offset()

def test_unpackparser_raises_exception(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GifUnpackParser(opened_md, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = p.parse_from_offset()

# TODO: check how relevant this test is, as the processing loop will never instantiate
# an UnpackParser for an empty file.
def test_all_unpack_parsers_raise_exception_on_empty_file(scan_environment, unpackparser):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'empty'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        up = unpackparser(opened_md, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            r = up.parse_from_offset()
            pytest.fail("%s accepts empty file" % unpackparser.__name__)

