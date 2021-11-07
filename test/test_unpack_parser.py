import pytest

from util import *
from bang.UnpackParserException import UnpackParserException
from bang.UnpackParser import UnpackParser
from bang.bangsignatures import get_unpackers, get_unpacker_by_pretty_name
from bang.parsers.database.sqlite.UnpackParser import SqliteUnpackParser
from bang.parsers.image.gif.UnpackParser import GifUnpackParser

class InvalidUnpackParser(UnpackParser):
    pass

@pytest.fixture(params = get_unpackers())
def unpackparser(request):
    return request.param

def parsers_and_test_files():
    return [
        (get_unpacker_by_pretty_name('cpio-new-ascii'), testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-new.cpio'),
        (get_unpacker_by_pretty_name('gif'), testdir_base / 'testdata' / 'unpackers' / 'gif' / 'test.gif'),
        (get_unpacker_by_pretty_name('png'), testdir_base / 'testdata' / 'unpackers' / 'png' / 'test.png'),
        (get_unpacker_by_pretty_name('fat'), testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test.fat'),
        (get_unpacker_by_pretty_name('fat'), testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'),
        (get_unpacker_by_pretty_name('gimpbrush'), testdir_base / 'testdata' / 'unpackers' / 'gimpbrush' / 'test.gbr'),
        (get_unpacker_by_pretty_name('ico'), testdir_base / 'testdata' / 'unpackers' / 'ico' / 'test.ico'),
        (get_unpacker_by_pretty_name('ihex'), testdir_base / 'testdata' / 'unpackers' / 'ihex' / 'example.hex'),
    ]


@pytest.fixture(params = parsers_and_test_files())
def parser_and_test_file(request):
    return request.param

def test_parsed_size_correct_with_offset(scan_environment, parser_and_test_file):
    unpack_parser_cls, test_path = parser_and_test_file
    offset = 128
    offset_path = scan_environment.temporarydirectory / f'offset_{test_path.name}'
    expected_size = test_path.stat().st_size
    with offset_path.open('wb') as outfile:
        outfile.write(b'A' * offset)
        with test_path.open('rb') as infile:
            # TODO: sendfile gives an OSError here
            #os.sendfile(outfile.fileno(), infile.fileno(), 0, expected_size)
            outfile.write(infile.read())

    md = create_meta_directory_for_path(scan_environment, offset_path, True)
    with md.open() as opened_md:
        p = unpack_parser_cls(opened_md, offset)
        p.parse_from_offset()
        assert p.parsed_size == expected_size

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

