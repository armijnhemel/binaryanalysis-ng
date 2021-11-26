from util import *
from bang.meta_directory import *
from bang.scan_job import *
from mock_queue import *
from bang.UnpackParser import PaddingParser
from bang.log import log

class UnpackParserUnpacksBase(UnpackParser):
    pretty_name = 'UnpackParserUnpacksRelative'
    extensions = []
    signatures = [(1,b'AA')]
    length = 5

    labels = []
    metadata = {}

    filenames = [ ]

    def parse(self):
        pass

    def calculate_unpacked_size(self):
        self.unpacked_size = self.length

    def unpack(self, meta_directory):
        log.debug(f'UnpackParserUnpacksRelative::unpack: unpacking')
        for fn in self.filenames:
            log.debug(f'UnpackParserUnpacksRelative::unpack: unpacking {fn!r}')
            with meta_directory.unpack_regular_file(pathlib.Path(fn)) as (unpacked_md, f):
                log.debug(f'UnpackParserUnpacksRelative::unpack: write')
                f.write(b'x')
                yield unpacked_md

class UnpackParserUnpacksRelative(UnpackParserUnpacksBase):
    filenames = [ 'unpack1', 'unpack2' ]

class UnpackParserUnpacksAbsolute(UnpackParserUnpacksBase):
    filenames = [ '/unpack1', '/unpack2' ]

class UnpackParserPassAlwaysIfSuggested(UnpackParser):
    extensions = []
    signatures = []
    pretty_name = 'parser_pass_always_if_suggested'

    labels = [ 'suggested-test-value' ]
    metadata = {}

    def parse(self):
        pass

    def calculate_unpacked_size(self):
        self.unpacked_size = self.infile.size

class UnpackParserFailAlwaysIfSuggested(UnpackParser):
    extensions = []
    signatures = []
    pretty_name = 'parser_fail_always_if_suggested'

    labels = [ 'suggested-test-value' ]
    metadata = {}



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

def queue_file_job(scan_environment, md):
    scanjob = ScanJob(md.md_path) # TODO: add context and parent? or are they in the md?
    scan_environment.scan_queue.put(scanjob)
    return scanjob

def run_scan_loop(scan_environment):
    try:
        process_jobs(make_scan_pipeline(), scan_environment)
    except queue.Empty:
        pass



######################################

# TODO: Tests for MetaDirectory, e.g. is the extracted/unpacked md.file_path relative?

######################################

# Tests for detecting padding files
def test_detect_padding_file(scan_environment):
    fn = pathlib.Path('test_padding.data')
    create_test_file(scan_environment, fn, b'\xff'*300)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert 'padding' in md.info.get('labels', [])
        assert sorted(md.extracted_files.keys()) == []

def test_detect_non_padding_file(scan_environment):
    fn = pathlib.Path('test_padding.data')
    create_test_file(scan_environment, fn, b'\xff'*299 + b'A')
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert 'padding' not in md.info.get('labels', [])

def test_detect_empty_file(scan_environment):
    fn = pathlib.Path('test_empty.data')
    create_test_file(scan_environment, fn, b'')
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert md.info.get('labels', []) == [] # TODO what to check?
        assert sorted(md.extracted_files.keys()) == []


######################################

# Tests for extracting during an extension based scan

from bang.parsers.image.gif.UnpackParser import GifUnpackParser

class ExtensionOnlyGifUnpackParser(GifUnpackParser):
    signatures = []


def test_extscan_extract_gif_file_full_file(scan_environment):
    fn = testdir_base / 'testdata' / pathlib.Path('unpackers') / 'gif' / 'test.gif'
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [ExtensionOnlyGifUnpackParser]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == []
        assert md.file_path == fn
        # assert md.info.get(...)


def test_extscan_extract_gif_file_prepended_data(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = b'x'*128 + f.read()
    fn = pathlib.Path('test_gif_prepended.gif')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [ExtensionOnlyGifUnpackParser]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    assert not path_md.is_scanned()
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [ ]
 
def test_extscan_extract_gif_file_appended_data(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = f.read() + b'x'*128
    fn = pathlib.Path('test_gif_appended.gif')
    abs_fn = create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [ExtensionOnlyGifUnpackParser]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert md.abs_file_path == abs_fn
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0, md.size - 128),
            md.extracted_filename(md.size - 128, 128)
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
    scan_environment.parsers.unpackparsers = [parser_pass_AA_1_5, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    #   |   ||        ||   ||       |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,5),
            md.extracted_filename(5,10),
            md.extracted_filename(15,5),
            md.extracted_filename(20,len(s)-20)
        ]

    md_ex1 = md.extracted_md(5, 10)
    with md_ex1.open(open_file=False):
        assert 'synthesized' in md_ex1.info.get('labels', [])

# 2. overlapping files with unpackers that extract during scan
def test_sigscan_extract_overlapping_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_pass_AA_1_5, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |   ||          |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,5),
            md.extracted_filename(5,len(s)-5)
        ]


# 3. same offset, different unpackers: one extracts, the other does not
# Note: disables, because order really depends on the automaton.
def x_test_sigscan_extract_same_offset_first_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_pass_BB_1_5, parser_fail_BB_1]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |  |   ||       |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,3),
            md.extracted_filename(3,5),
            md.extracted_filename(8,len(s)-8)
        ]

def x_test_sigscan_extract_same_offset_second_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_fail_BB_1, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |  |   ||       |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,3),
            md.extracted_filename(3,5),
            md.extracted_filename(8,len(s)-8)
        ]

def test_sigscan_extract_overlapping_different_offset_both_successful(scan_environment):
    s = b'xAAyyyyyyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_pass_AA_1_5, parser_pass_BB_8_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyyyyyyBBxxxxxxxxxxx'
    #   |   ||               |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,5),
            md.extracted_filename(5,len(s)-5)
        ]

# 4. same offset, different unpackers that both unpack (polyglot)
# e.g. iso image containing an image in the first block
# -> first parser wins
def x_test_sigscan_extract_same_offset_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_pass_BB_1_5, parser_pass_BB_1_7]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   | ||   ||       |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,3),
            md.extracted_filename(3,5),
            md.extracted_filename(8,len(s)-8)
        ]

def x_test_sigscan_extract_same_offset_both_successful_reversed_order(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_pass_BB_1_7, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   | ||   ||       |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,3),
            md.extracted_filename(3,7),
            md.extracted_filename(10,len(s)-10)
        ]

# 5. files with unpackers that do not unpack
def test_sigscan_extract_overlapping_none_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_fail_AA_1, parser_fail_BB_1]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |               |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [ ]

def test_sigscan_extract_parse_successful_at_end(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_fail_BB_1, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBbb'
    #   | ||   |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,3),
            md.extracted_filename(3,5)
        ]

def test_sigscan_extracting_overlapping_successful_parsers(scan_environment):
    s = b'--xAAyBBbCCxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_pass_AA_1_5,
        parser_pass_BB_1_5, parser_pass_CC_0_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'--xAAyBBbCCxxxxxxxx'
    #   |||...||||...||   |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,2),
            md.extracted_filename(2,5),
            md.extracted_filename(7,2),
            md.extracted_filename(9,5),
            md.extracted_filename(14,len(s)-14)
        ]

def test_sigscan_extracting_parses_whole_string(scan_environment):
    s = b'xBBxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_fail_BB_1, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'--xAAyBBbCCxxxxxxxx'
    #   |||...||||...||   |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == []

# test: prevent infinite extractions from zero length files.
def test_sigscan_extract_with_zero_length_parser(scan_environment):
    s = b'xBBxx12345'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [UnpackParserZeroLength, parser_pass_BB_0_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xBBxx12345'
    #   ||...||  |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,1),
            md.extracted_filename(1,5),
            md.extracted_filename(6,len(s)-6)
        ]



def test_extract_suggested_parser_unpacks(scan_environment):
    s = b'xBBxx12'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    with path_md.open(open_file=False):
        path_md.info['suggested_parsers'] = [ 'pass-BB-1-7' ]
    scan_environment.parsers.unpackparsers = [ parser_pass_BB_1_5, parser_pass_BB_1_7 ]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == []
        assert md.info['unpack_parser'] == 'pass-BB-1-7'


def test_extract_only_suggested_parser_unpacks(scan_environment):
    fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "ihex" / "example.txt"
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    with path_md.open(open_file=False):
        path_md.info['suggested_parsers'] = [ 'parser_pass_always_if_suggested' ]
    scan_environment.parsers.add(UnpackParserPassAlwaysIfSuggested)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert md.info.get('labels') == [ 'suggested-test-value' ]

def test_extract_suggested_parser_failing(scan_environment):
    fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "ihex" / "example.txt"
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    with path_md.open(open_file=False):
        path_md.info['suggested_parsers'] = [ 'parser_fail_always_if_suggested' ]
    scan_environment.parsers.add(UnpackParserFailAlwaysIfSuggested)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert md.unpacked_path(pathlib.Path('unpacked-from-ihex')) in md.unpacked_files

#######

# Test properties for extracted files

def test_extracted_file_has_parent(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_fail_BB_1, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBbb'
    #   | ||   |
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,3),
            md.extracted_filename(3,5)
        ]
        with md.extracted_md(3,5).open() as sub_md:
            assert sub_md.info.get('parent_md') == md.md_path

################

# test processing with parsers that unpack files

def test_unpacking_parser_unpacks_relative_files(scan_environment):
    s = b'xAAyy'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [UnpackParserUnpacksRelative]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == []
        expected_files = [ md.unpacked_path(pathlib.Path(x)) for x in UnpackParserUnpacksRelative.filenames ]
        assert list(md.unpacked_files.keys()) == expected_files
        assert all(p.is_relative_to(md.unpacked_rel_root) for p, _ in md.unpacked_files.items())

def test_unpacking_parser_unpacks_absolute_files(scan_environment):
    s = b'xAAyy'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [UnpackParserUnpacksAbsolute]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == []
        expected_files = [ md.unpacked_path(pathlib.Path(x)) for x in UnpackParserUnpacksAbsolute.filenames ]
        assert list(md.unpacked_files.keys()) == expected_files
        assert all(p.is_relative_to(md.unpacked_abs_root) for p, _ in md.unpacked_files.items())

################

# test extracted and unpacked files are queued

def test_extracted_file_is_queued(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [parser_fail_BB_1, parser_pass_BB_1_5]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    # b'xAAyBBbb'
    #   | ||   |
    jobs_queued = [x for x in scan_environment.scan_queue.history if x != -1]
    assert len(jobs_queued) == 2

def test_unpacked_file_is_queued(scan_environment):
    s = b'xAAyy'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.unpackparsers = [UnpackParserUnpacksAbsolute]
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    jobs_queued = [x for x in scan_environment.scan_queue.history if x != -1]
    assert len(jobs_queued) == 3



################

# test processing with real parsers

def test_sigscan_extract_gif_file_from_prepended_file(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = b'x'*128 + f.read()
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)

    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert sorted(md.extracted_files.keys()) == [
            md.extracted_filename(0,128),
            md.extracted_filename(128, md.size-128)
        ]

####################
# Featureless parser


def test_parse_featureless_file(scan_environment):
    fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "ihex" / "example.txt"
    path_md = create_meta_directory_for_path(scan_environment, fn, True)
    scan_environment.parsers.build_automaton()
    scanjob = queue_file_job(scan_environment, path_md)
    run_scan_loop(scan_environment)
    with reopen_md(path_md).open(open_file=False) as md:
        assert md.unpacked_path(pathlib.Path('unpacked-from-ihex')) in md.unpacked_files


