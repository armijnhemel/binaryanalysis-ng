from .util import *
from unpack_directory import *
from scan_job import *
from .mock_queue import *
from UnpackParser import PaddingParser

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

def create_unpack_directory_for_path(scan_environment, path, is_root):
    path_ud = UnpackDirectory(scan_environment.unpackdirectory, None, is_root)
    path_ud.file_path = scan_environment.temporarydirectory / path
    return path_ud

def queue_file_job(scan_environment, ud):
    scanjob = ScanJob(ud.ud_path) # TODO: parent?
    scan_environment.scanfilequeue.put(scanjob)
    return scanjob

def run_scan_loop(scan_environment):
    try:
        process_jobs(scan_environment)
    except QueueEmptyError:
        pass


######################################

# TODO: Tests for unpack directory, is extracted/unpacked ud.file_path relative?

######################################

# Tests for detecting padding files
def test_detect_padding_file(scan_environment):
    fn = pathlib.Path('test_padding.data')
    create_test_file(scan_environment, fn, b'\xff'*300)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    assert 'padding' in path_ud.info.get('labels', [])
    assert sorted(path_ud.extracted_files.keys()) == []

def test_detect_non_padding_file(scan_environment):
    fn = pathlib.Path('test_padding.data')
    create_test_file(scan_environment, fn, b'\xff'*299 + b'A')
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    assert 'padding' not in path_ud.info.get('labels', [])

def test_detect_empty_file(scan_environment):
    fn = pathlib.Path('test_empty.data')
    create_test_file(scan_environment, fn, b'')
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    assert path_ud.info.get('labels', []) == [] # TODO what to check?
    assert sorted(path_ud.extracted_files.keys()) == []


######################################

# Tests for extracting during an extension based scan

from parsers.image.gif.UnpackParser import GifUnpackParser

class ExtensionOnlyGifUnpackParser(GifUnpackParser):
    signatures = []


def test_extscan_extract_gif_file_full_file(scan_environment):
    fn = testdir_base / 'testdata' / pathlib.Path('unpackers') / 'gif' / 'test.gif'
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([ExtensionOnlyGifUnpackParser])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    assert sorted(path_ud.extracted_files.keys()) == []
    assert path_ud.file_path == fn
    # assert path_ud.info.get(...)


def test_extscan_extract_gif_file_prepended_data(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = b'x'*128 + f.read()
    fn = pathlib.Path('test_gif_prepended.gif')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([ExtensionOnlyGifUnpackParser])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    assert not path_ud.is_scanned()
    assert sorted(path_ud.extracted_files.keys()) == [ ]
 
def test_extscan_extract_gif_file_appended_data(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = f.read() + b'x'*128
    fn = pathlib.Path('test_gif_appended.gif')
    abs_fn = create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([ExtensionOnlyGifUnpackParser])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    assert path_ud.abs_file_path == abs_fn
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0, path_ud.size - 128),
        path_ud.extracted_filename(path_ud.size - 128, 128)
    ]
    # TODO: check if extracted gif file contains the data
    # TODO: check that path_ud does not contain any gif metadata
    # assert path_ud.info.get(...)
 
######################################

# Tests for extracting during a signature based scan

# 1. non-overlapping files with unpackers that extract during scan
def test_sigscan_extract_non_overlapping_both_successful(scan_environment):
    s = b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack1.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    #   |   ||        ||   ||       |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,5),
        path_ud.extracted_filename(5,10),
        path_ud.extracted_filename(15,5),
        path_ud.extracted_filename(20,len(s)-20)
    ]

    syn1 = path_ud.extracted_filename(5,10)
    ud_syn1 = UnpackDirectory.from_ud_path(scan_environment.unpackdirectory, path_ud.extracted_files[syn1])
    assert 'synthesized' in ud_syn1.info.get('labels', [])

# 2. overlapping files with unpackers that extract during scan
def test_sigscan_extract_overlapping_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |   ||          |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,5),
        path_ud.extracted_filename(5,len(s)-5)
    ]


# 3. same offset, different unpackers: one extracts, the other does not
def test_sigscan_extract_same_offset_first_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_BB_1_5, parser_fail_BB_1])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |  |   ||       |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,3),
        path_ud.extracted_filename(3,5),
        path_ud.extracted_filename(8,len(s)-8)
    ]

def test_sigscan_extract_same_offset_second_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |  |   ||       |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,3),
        path_ud.extracted_filename(3,5),
        path_ud.extracted_filename(8,len(s)-8)
    ]

def test_sigscan_extract_overlapping_different_offset_both_successful(scan_environment):
    s = b'xAAyyyyyyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_8_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyyyyyyBBxxxxxxxxxxx'
    #   |   ||               |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,5),
        path_ud.extracted_filename(5,len(s)-5)
    ]

# 4. same offset, different unpackers that both unpack (polyglot)
# e.g. iso image containing an image in the first block
# -> first parser wins
def test_sigscan_extract_same_offset_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_BB_1_5, parser_pass_BB_1_7])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   | ||   ||       |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,3),
        path_ud.extracted_filename(3,5),
        path_ud.extracted_filename(8,len(s)-8)
    ]

def test_sigscan_extract_same_offset_both_successful_reversed_order(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_BB_1_7, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   | ||   ||       |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,3),
        path_ud.extracted_filename(3,7),
        path_ud.extracted_filename(10,len(s)-10)
    ]

# 5. files with unpackers that do not unpack
def test_sigscan_extract_overlapping_none_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_AA_1, parser_fail_BB_1])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBxxxxxxxxxxx'
    #   |               |
    assert sorted(path_ud.extracted_files.keys()) == [ ]

def test_sigscan_extract_parse_successful_at_end(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xAAyBBbb'
    #   | ||   |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,3),
        path_ud.extracted_filename(3,5)
    ]

def test_sigscan_extracting_overlapping_successful_parsers(scan_environment):
    s = b'--xAAyBBbCCxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5,
        parser_pass_BB_1_5, parser_pass_CC_0_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'--xAAyBBbCCxxxxxxxx'
    #   |||...||||...||   |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,2),
        path_ud.extracted_filename(2,5),
        path_ud.extracted_filename(7,2),
        path_ud.extracted_filename(9,5),
        path_ud.extracted_filename(14,len(s)-14)
    ]

def test_sigscan_extracting_parses_whole_string(scan_environment):
    s = b'xBBxx'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'--xAAyBBbCCxxxxxxxx'
    #   |||...||||...||   |
    assert sorted(path_ud.extracted_files.keys()) == []

# test: prevent infinite extractions from zero length files.
def test_sigscan_extract_with_zero_length_parser(scan_environment):
    s = b'xBBxx12345'
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)
    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    scan_environment.set_unpackparsers([UnpackParserZeroLength, parser_pass_BB_0_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)
    # b'xBBxx12345'
    #   ||...||  |
    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,1),
        path_ud.extracted_filename(1,5),
        path_ud.extracted_filename(6,len(s)-6)
    ]


################

# test unpacking with real parsers

def test_sigscan_extract_gif_file_from_prepended_file(scan_environment):
    gif_fn = testdir_base / 'testdata' / pathlib.Path("unpackers") / "gif" / "test.gif"
    with gif_fn.open('rb') as f:
        s = b'x'*128 + f.read()
    fn = pathlib.Path('test_unpack2.data')
    create_test_file(scan_environment, fn, s)

    path_ud = create_unpack_directory_for_path(scan_environment, fn, True)
    # scan_environment.set_unpackparsers([UnpackParserZeroLength, parser_pass_BB_0_5])
    scanjob = queue_file_job(scan_environment, path_ud)
    run_scan_loop(scan_environment)

    assert sorted(path_ud.extracted_files.keys()) == [
        path_ud.extracted_filename(0,128),
        path_ud.extracted_filename(128, path_ud.size-128)
    ]



