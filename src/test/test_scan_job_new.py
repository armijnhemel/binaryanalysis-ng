from .util import *
from unpack_directory import *
from scan_job import *
from .mock_queue import *

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


# 1. non-overlapping files with unpackers that unpack
def test_process_non_overlapping_both_successful(scan_environment):
    s = b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack1.data')
    path_ud = UnpackDirectory(scan_environment.unpackdirectory, None, True)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    path_ud.file_path = scan_environment.temporarydirectory / fn
    scanjob = ScanJob(path_ud.ud_path) # TODO: parent?
    scan_environment.scanfilequeue.put(scanjob)
    try:
        process_jobs(scan_environment)
    except QueueEmptyError:
        pass
    # b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    #   |   ||        ||   ||       |
    assert len(path_ud.extracted) == 4
    assert 'synthesized' in UnpackDirectory.from_ud_path(path_ud.extracted[0]).info['labels']

