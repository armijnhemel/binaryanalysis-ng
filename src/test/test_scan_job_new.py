import logging
from .util import *
from meta_directory import *
from scan_job import *
from .mock_queue import *
from UnpackParser import PaddingParser

class UnpackParserUnpacksBase(UnpackParser):
    pretty_name = 'UnpackParserUnpacksRelative'
    extensions = []
    signatures = [(1,b'AA')]
    length = 5

    filenames = [ ]

    def parse(self):
        pass

    def calculate_unpacked_size(self):
        self.unpacked_size = self.length

    def unpack(self, meta_directory):
        # TODO
        logging.debug(f'UnpackParserUnpacksRelative::unpack: unpacking')
        for fn in self.filenames:
            logging.debug(f'UnpackParserUnpacksRelative::unpack: unpacking {fn!r}')
            with meta_directory.unpack_regular_file(pathlib.Path(fn)) as (unpacked_md, f):
                logging.debug(f'UnpackParserUnpacksRelative::unpack: write')
                f.write(b'x')
                yield unpacked_md
                # TODO: yield new meta_directory

class UnpackParserUnpacksRelative(UnpackParserUnpacksBase):
    filenames = [ 'unpack1', 'unpack2' ]

class UnpackParserUnpacksAbsolute(UnpackParserUnpacksBase):
    filenames = [ '/unpack1', '/unpack2' ]

parser_pass_AA_1_5 = create_unpackparser('ParserPassAA_1_5',
        signatures = [(1,b'AA')],
        length = 5,
        pretty_name = 'pass-AA-1-5')
parser_pass_BB_1_5 = create_unpackparser('ParserPassBB_1_5',
        signatures = [(1,b'BB')],
        length = 5,
        pretty_name = 'pass-BB-1-5')
parser_pass_BB_8_5 = create_unpackparser('ParserPassBB_8_5',
        signatures = [(8,b'BB')],
        length = 5,
        pretty_name = 'pass-BB-8-5')
parser_pass_CC_0_5 = create_unpackparser('ParserPassCC_0_5',
        signatures = [(0,b'CC')],
        length = 5,
        pretty_name = 'pass-CC-0-5')
parser_fail_AA_1 = create_unpackparser('ParserFailAA_1',
        signatures = [(1,b'AA')],
        fail = True,
        pretty_name = 'fail-AA-1')
parser_fail_BB_1 = create_unpackparser('ParserFailBB_1',
        signatures = [(1,b'BB')],
        fail = True,
        pretty_name = 'fail-BB-1')
parser_pass_BB_1_7 = create_unpackparser('ParserPassBB_1_7',
        signatures = [(1,b'BB')],
        length = 7,
        pretty_name = 'pass-BB-1-7')
parser_pass_BB_0_5 = create_unpackparser('ParserPassBB_0_5',
        signatures = [(0,b'BB')],
        length = 5,
        pretty_name = 'pass-BB-0-5')

def create_test_file(scan_environment, path, content):
    abs_path = scan_environment.temporarydirectory / path
    with abs_path.open('wb') as f:
        f.write(content)
    return abs_path

def create_meta_directory_for_path(scan_environment, path, is_root):
    path_md = MetaDirectory(scan_environment.unpackdirectory, None, is_root)
    path_md.file_path = scan_environment.temporarydirectory / path
    return path_md

def queue_file_job(scan_environment, md):
    scanjob = ScanJob(md.md_path) # TODO: add context and parent? or are they in the md?
    scan_environment.scanfilequeue.put(scanjob)
    return scanjob

def run_scan_loop(scan_environment):
    try:
        process_jobs(scan_environment)
    except QueueEmptyError:
        pass


######################################

# TODO: Tests for MetaDirectory, e.g. is the extracted/unpacked md.file_path relative?

######################################

# Tests for detecting padding files
def test_detect_padding_file(scan_environment):
    fn = pathlib.Path('test_padding.data')
    create_test_file(scan_environment, fn, b'\xff'*300)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert 'padding' in path_md.info.get('labels', [])
    assert sorted(path_md.extracted_files.keys()) == []

def test_detect_non_padding_file(scan_environment):
    fn = pathlib.Path('test_padding.data')
    create_test_file(scan_environment, fn, b'\xff'*299 + b'A')
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert 'padding' not in path_md.info.get('labels', [])

def test_detect_empty_file(scan_environment):
    fn = pathlib.Path('test_empty.data')
    create_test_file(scan_environment, fn, b'')
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert path_md.info.get('labels', []) == [] # TODO what to check?
    assert sorted(path_md.extracted_files.keys()) == []


######################################

# Tests for extracting during an extension based scan

from parsers.image.gif.UnpackParser import GifUnpackParser

class ExtensionOnlyGifUnpackParser(GifUnpackParser):
    signatures = []


def test_extscan_extract_gif_file_full_file(scan_environment):
    fn = testdir_base / 'testdata' / pathlib.Path('unpackers') / 'gif' / 'test.gif'
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([ExtensionOnlyGifUnpackParser])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert sorted(path_md.extracted_files.keys()) == []
    assert path_md.file_path == fn
    # assert path_md.info.get(...)


def test_extscan_extract_gif_file_prepended_data(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = b'x'*128 + f.read()
    fn = pathlib.Path('test_gif_prepended.gif')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([ExtensionOnlyGifUnpackParser])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert not path_md.is_scanned()
    assert sorted(path_md.extracted_files.keys()) == [ ]
 
def test_extscan_extract_gif_file_appended_data(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = f.read() + b'x'*128
    fn = pathlib.Path('test_gif_appended.gif')
    abs_fn = create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([ExtensionOnlyGifUnpackParser])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert path_md.abs_file_path == abs_fn
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0, path_md.size - 128),
        path_md.extracted_filename(path_md.size - 128, 128)
    ]
    # TODO: check if extracted gif file contains the data
    # TODO: check that path_md does not contain any gif metadata
    # assert path_md.info.get(...)
 
######################################

# Tests for extracting during a signature based scan

# 1. non-overlapping files with unpackers that extract during scan
def test_sigscan_extract_non_overlapping_both_successful(scan_environment):
    s = b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack1.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    #   |   ||        ||   ||       |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,5),
        path_md.extracted_filename(5,10),
        path_md.extracted_filename(15,5),
        path_md.extracted_filename(20,len(s)-20)
    ]

    md_ex1 = path_md.extracted_md(5, 10)
    assert 'synthesized' in md_ex1.info.get('labels', [])

# 2. overlapping files with unpackers that extract during scan
def test_sigscan_extract_overlapping_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |   ||          |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,5),
        path_md.extracted_filename(5,len(s)-5)
    ]


# 3. same offset, different unpackers: one extracts, the other does not
def test_sigscan_extract_same_offset_first_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_BB_1_5, parser_fail_BB_1])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |  |   ||       |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,3),
        path_md.extracted_filename(3,5),
        path_md.extracted_filename(8,len(s)-8)
    ]

def test_sigscan_extract_same_offset_second_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |  |   ||       |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,3),
        path_md.extracted_filename(3,5),
        path_md.extracted_filename(8,len(s)-8)
    ]

def test_sigscan_extract_overlapping_different_offset_both_successful(scan_environment):
    s = b'xAAyyyyyyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_8_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyyyyyyBBxxxxxxxxxxx'
    #   |   ||               |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,5),
        path_md.extracted_filename(5,len(s)-5)
    ]

# 4. same offset, different unpackers that both unpack (polyglot)
# e.g. iso image containing an image in the first block
# -> first parser wins
def test_sigscan_extract_same_offset_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_BB_1_5, parser_pass_BB_1_7])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   | ||   ||       |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,3),
        path_md.extracted_filename(3,5),
        path_md.extracted_filename(8,len(s)-8)
    ]

def test_sigscan_extract_same_offset_both_successful_reversed_order(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_BB_1_7, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   | ||   ||       |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,3),
        path_md.extracted_filename(3,7),
        path_md.extracted_filename(10,len(s)-10)
    ]

# 5. files with unpackers that do not unpack
def test_sigscan_extract_overlapping_none_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_AA_1, parser_fail_BB_1])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |               |
    assert sorted(path_md.extracted_files.keys()) == [ ]

def test_sigscan_extract_parse_successful_at_end(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBbb'
    #   | ||   |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,3),
        path_md.extracted_filename(3,5)
    ]

def test_sigscan_extracting_overlapping_successful_parsers(scan_environment):
    s = b'--xAAyBBbCCxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5,
        parser_pass_BB_1_5, parser_pass_CC_0_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'--xAAyBBbCCxxxxxxxx'
    #   |||...||||...||   |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,2),
        path_md.extracted_filename(2,5),
        path_md.extracted_filename(7,2),
        path_md.extracted_filename(9,5),
        path_md.extracted_filename(14,len(s)-14)
    ]

def test_sigscan_extracting_parses_whole_string(scan_environment):
    s = b'xBBxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'--xAAyBBbCCxxxxxxxx'
    #   |||...||||...||   |
    assert sorted(path_md.extracted_files.keys()) == []

# test: prevent infinite extractions from zero length files.
def test_sigscan_extract_with_zero_length_parser(scan_environment):
    s = b'xBBxx12345'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([UnpackParserZeroLength, parser_pass_BB_0_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xBBxx12345'
    #   ||...||  |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,1),
        path_md.extracted_filename(1,5),
        path_md.extracted_filename(6,len(s)-6)
    ]


#######

# Test properties for extracted files

def test_extracted_file_has_parent(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBbb'
    #   | ||   |
    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,3),
        path_md.extracted_filename(3,5)
    ]
    assert path_md.extracted_md(3,5).info.get('parent_md') == path_md.md_path

################

# test processing with parsers that unpack files

def test_unpacking_parser_unpacks_relative_files(scan_environment):
    s = b'xAAyy'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([UnpackParserUnpacksRelative])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert sorted(path_md.extracted_files.keys()) == []
    expected_files = [ path_md.unpacked_path(pathlib.Path(x)) for x in UnpackParserUnpacksRelative.filenames ]
    assert list(path_md.unpacked_files.keys()) == expected_files
    assert all(p.is_relative_to(path_md.unpacked_rel_root) for p, md in path_md.unpacked_files.items())

def test_unpacking_parser_unpacks_absolute_files(scan_environment):
    s = b'xAAyy'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([UnpackParserUnpacksAbsolute])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert sorted(path_md.extracted_files.keys()) == []
    expected_files = [ path_md.unpacked_path(pathlib.Path(x)) for x in UnpackParserUnpacksAbsolute.filenames ]
    assert list(path_md.unpacked_files.keys()) == expected_files
    assert all(p.is_relative_to(path_md.unpacked_abs_root) for p, md in path_md.unpacked_files.items())

################

# test processing with real parsers

def test_sigscan_extract_gif_file_from_prepended_file(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = b'x'*128 + f.read()
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)

    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    # scan_environment.set_unpackparsers([UnpackParserZeroLength, parser_pass_BB_0_5])
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)

    assert sorted(path_md.extracted_files.keys()) == [
        path_md.extracted_filename(0,128),
        path_md.extracted_filename(128, path_md.size-128)
    ]



