import sys
import os
import shutil
import pathlib
import inspect
# import unittest

from .util import *

from FileResult import *
from ScanJob import *
# from ScanEnvironment import *

# import bangfilescans

testdata_dir = testdir_base / 'testdata'

# TODO: this violates the FileResult API, which requires a relative path!
def create_tmp_fileresult(path_abs, content):
    with open(path_abs, 'wb') as f:
        f.write(content)
    fileresult = FileResult(None, path_abs, set())
    fileresult.set_filesize(path_abs.stat().st_size)
    return fileresult

def _create_padding_file_in_unpack_directory(scan_environment):
    parent_dir = pathlib.Path('a')
    padding_file = pathlib.Path('a') / 'PADDING-0x00-0x01'
    padding_file_abs = scan_environment.unpackdirectory / padding_file
    padding_file_abs.parent.mkdir(parents=True, exist_ok=True)
    with padding_file_abs.open('wb') as f:
        f.write(b'\0' * 20)
    return padding_file

def initialize_scanjob_and_unpacker(scan_environment, fileresult):
    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpacker = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    return scanjob, unpacker

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


# TODO: test unpacking for extension that has multiple unpackparsers

def test_carved_padding_file_has_correct_labels(scan_environment):
    padding_file = _create_padding_file_in_unpack_directory(scan_environment)
    fileresult = FileResult(None, padding_file, set())
    fileresult.set_filesize(
            (scan_environment.unpackdirectory / padding_file).stat().st_size)
    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpacker = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_unscannable_file()
    unpacker.append_unpacked_range(0, 5) # bytes [0:5) are unpacked
    scanjob.carve_file_data(unpacker)
    j = scan_environment.scanfilequeue.get()
    assert j.fileresult.labels == set(['padding', 'synthesized'])

def test_process_paddingfile_has_correct_labels(scan_environment):
    padding_file = _create_padding_file_in_unpack_directory(scan_environment)
    fileresult = FileResult(None, padding_file, set(['padding']))
    fileresult.set_filesize(
            (scan_environment.unpackdirectory / padding_file).stat().st_size)
    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    result = scan_environment.resultqueue.get()
    assert result.labels == set(['binary', 'padding'])

def test_process_css_file_has_correct_labels(scan_environment):
    # /home/tim/bang-test-scrap/bang-scan-jucli3nm/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/www/luci-static/bootstrap/cascade.css
    fn = pathlib.Path("a/cascade.css")
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)
    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    result = scan_environment.resultqueue.get()
    assert result.labels == set(['binary', 'css'])

def test_openwrt_version_has_correct_labels(scan_environment):
    # openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/etc/openwrt_version
    fn = pathlib.Path("a/openwrt_version")
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as ex:
        if ex.e.__class__ != QueueEmptyError:
            raise ex
    result = scan_environment.resultqueue.get()
    assert result.labels == set(['text', 'base64', 'urlsafe'])

def test_dhcpv6sh_has_correct_labels(scan_environment):
    # /home/tim/bang-test-scrap/bang-scan-wd8il1i5/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/lib/netifd/proto/dhcpv6.sh
    fn = pathlib.Path("a/dhcpv6.sh")
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)
    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    result = scan_environment.resultqueue.get()
    assert result.labels == set(['text', 'script', 'shell'])

def test_kernelconfig_is_processed(scan_environment):
    # rel_testfile = pathlib.Path('unpackers') / 'kernelconfig' / 'kernelconfig'
    rel_testfile = pathlib.Path('download') / 'system'/ 'kernelconfig' / 'tiny.config'
    abs_testfile = testdata_dir / rel_testfile
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, abs_testfile, set())
    fileresult.set_filesize(abs_testfile.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    result = scan_environment.resultqueue.get()

    assert result.filename == abs_testfile
    assert result.labels == set(['text', 'kernel configuration'])

def test_gzip_unpacks_to_right_directory(scan_environment):
    fn = pathlib.Path("a") / "hello.gz"
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    result1 = scan_environment.resultqueue.get()
    result2 = scan_environment.resultqueue.get()
    fn_expected = pathlib.Path(fn.name+'-0x00000000-gzip-1') / 'hello'
    assert result2.filename == fn_expected

def test_report_has_correct_path(scan_environment):
    fn = pathlib.Path("a") / "hello.gz"
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    result1 = scan_environment.resultqueue.get()
    result2 = scan_environment.resultqueue.get()
    unpack_report = result1.unpackedfiles[0]
    fn_expected = pathlib.Path(fn.name+'-0x00000000-gzip-1') / 'hello'

    assert unpack_report['unpackdirectory'] == str(fn_expected.parent)
    assert unpack_report['files'] == [ str(fn_expected) ]

def test_file_is_unpacked_by_extension(scan_environment):
    fn = pathlib.Path("unpackers") / "gif" / "test.gif"
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpacker = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpacker)
    assert 'gif' in fileresult.labels

def test_file_unpack_extension_success(scan_environment):
    fn = pathlib.Path("test.ex1")
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, b"A"*70)
    scan_environment.set_unpackparsers([UnpackParserExtractEx1])
    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpack_manager)

    unpack_report = fileresult.unpackedfiles[0]
    assert len(unpack_report['files']) == 2
    fn1 = unpack_manager.get_data_unpack_directory() / "ex1_first"
    fn2 = unpack_manager.get_data_unpack_directory() / "ex1_second"
    assert unpack_report['files'][0] == fn1
    assert unpack_report['files'][1] == fn2
    assertUnpackedPathExists(scan_environment, unpack_report['files'][0])
    assertUnpackedPathExists(scan_environment, unpack_report['files'][1])

def test_file_unpack_extension_carve(scan_environment):
    fn = pathlib.Path("test.ex1")
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, b"A"*70)
    scan_environment.set_unpackparsers([UnpackParserExtractEx1Carve])
    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpack_manager)

    unpack_report = fileresult.unpackedfiles[0]
    assert len(unpack_report['files']) == 3
    fn1 = unpack_manager.get_data_unpack_directory() / "ex1_first"
    fn2 = unpack_manager.get_data_unpack_directory() / "ex1_second"
    fn3 = unpack_manager.get_data_unpack_directory() / "unpacked.ex1_extract_carve"
    assert unpack_report['files'][0] == fn1
    assert unpack_report['files'][1] == fn2
    assert unpack_report['files'][2] == fn3
    assertUnpackedPathExists(scan_environment, unpack_report['files'][0])
    assertUnpackedPathExists(scan_environment, unpack_report['files'][1])
    assertUnpackedPathExists(scan_environment, unpack_report['files'][2])

def test_file_unpack_extension_fail(scan_environment):
    fn = pathlib.Path("test.ex1")
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, b"A"*70)
    scan_environment.set_unpackparsers([UnpackParserExtractEx1Fail])
    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpack_manager)

    assertUnpackedPathDoesNotExist(scan_environment, unpack_manager.get_data_unpack_directory())

    assert fileresult.unpackedfiles == []





def test_file_is_unpacked_by_signature(scan_environment):
    fn = pathlib.Path("unpackers") / "gif" / "test-prepend-random-data.gif"
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpacker = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpacker)
    assert 'gif' not in fileresult.labels
    scanjob.check_for_signatures(unpacker)
    assert 'gif' not in fileresult.labels
    j = scan_environment.scanfilequeue.get()
    assert 'gif' in j.fileresult.labels

def test_carved_data_is_extracted_from_file(scan_environment):
    fn = pathlib.Path("unpackers") / "gif" / "test-prepend-random-data.gif"
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpacker = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpacker)
    scanjob.check_for_signatures(unpacker)
    j = scan_environment.scanfilequeue.get()
    scanjob.carve_file_data(unpacker)
    j = scan_environment.scanfilequeue.get()
    synthesized_name = pathlib.Path('.') / \
            ("%s-0x%08x-synthesized-1" % (fn.name,0)) / \
            ("unpacked-0x%x-0x%x" % (0,127))
    assert j.fileresult.filename == synthesized_name
    assertUnpackedPathExists(scan_environment, j.fileresult.filename)

def test_featureless_file_is_unpacked(scan_environment):
    fn = pathlib.Path("unpackers") / "ihex" / "example.txt"
    fn_abs = testdata_dir / fn
    # TODO: FileResult asks for relative path
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scanjob.set_scanenvironment(scan_environment)
    scanjob.initialize()
    unpacker = UnpackManager(scan_environment.unpackdirectory)
    scanjob.prepare_for_unpacking()
    scanjob.check_for_valid_extension(unpacker)
    assert fileresult.labels == set()
    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert fileresult.unpackedfiles == []
    scanjob.carve_file_data(unpacker)
    assert fileresult.unpackedfiles == []
    fileresult.labels.add('text')
    scanjob.check_entire_file(unpacker)
    assert len(fileresult.unpackedfiles) == 1
    j = scan_environment.scanfilequeue.get()
    expected_extracted_fn = pathlib.Path('.') / \
            ("%s-0x%08x-ihex-1" % (fn.name, 0)) / "unpacked-from-ihex"
    assert j.fileresult.filename == expected_extracted_fn
    assertUnpackedPathExists(scan_environment, j.fileresult.filename)

# test to verify how signatures are matched
# 1. non-overlapping files with unpackers that unpack
def test_unpack_non_overlapping_both_successful(scan_environment):
    s = b'xAAxxxxxxxxxxxxyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack1.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    # TODO: check if this is what we want
    assert len(fileresult.unpackedfiles) == 2
    upf0 = fileresult.unpackedfiles[0]
    upf1 = fileresult.unpackedfiles[1]
    assert upf0['offset'] == 0
    assert upf1['offset'] == 15

# 2. overlapping files with unpackers that unpack
def test_unpack_overlapping_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    # TODO: check if this is what we want
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 0

def test_unpack_overlapping_first_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5, parser_fail_BB_1])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 0


def test_unpack_overlapping_second_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_AA_1, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 3

# 3. same offset, different unpackers: one unpacks, the other does not
def test_unpack_same_offset_first_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_BB_1_5, parser_fail_BB_1])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 3

def test_unpack_same_offset_second_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 3

def test_unpack_overlapping_different_offset_both_successful(scan_environment):
    s = b'xAAyyyyyyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5,
        parser_pass_BB_8_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 0


# 4. same offset, different unpackers that both unpack (polyglot)
# e.g. iso image containing an image in the first block
# -> first parser wins
def test_unpack_same_offset_both_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_BB_1_5, parser_pass_BB_1_7])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    # TODO: check if this is what we want
    assert len(fileresult.unpackedfiles) == 1
    upf0 = fileresult.unpackedfiles[0]
    assert upf0['offset'] == 3
    # unpackparser order is undeterministic,
    # we can't tell which parser parsed
    # assert upf0['size'] == 5

# 5. files with unpackers that do not unpack
def test_unpack_overlapping_none_successful(scan_environment):
    s = b'xAAyBBxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_AA_1, parser_fail_BB_1])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    assert fileresult.labels == set()
    assert len(fileresult.unpackedfiles) == 0

def test_carving_one_unpack_successful(scan_environment):
    s = b'xAAyBBbbxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    scanjob.carve_file_data(unpacker)
    assert fileresult.labels == set()
    upfiles = fileresult.unpackedfiles
    assert len(upfiles) == 3
    assert upfiles[0]['offset'] == 3
    assert upfiles[0]['size'] == 5
    assert upfiles[1]['offset'] == 0
    assert upfiles[1]['size'] == 3
    assert upfiles[2]['offset'] == 8
    assert upfiles[2]['size'] == len(s) - 8

def test_carving_one_unpack_successful_at_end(scan_environment):
    s = b'xAAyBBbb'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    scanjob.carve_file_data(unpacker)
    assert fileresult.labels == set()
    upfiles = fileresult.unpackedfiles
    assert len(upfiles) == 2
    assert upfiles[0]['offset'] == 3
    assert upfiles[0]['size'] == 5
    assert upfiles[1]['offset'] == 0
    assert upfiles[1]['size'] == 3

def test_carving_overlapping_unpacks_successful(scan_environment):
    s = b'--xAAyBBbCCxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_pass_AA_1_5,
        parser_pass_BB_1_5, parser_pass_CC_0_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    scanjob.carve_file_data(unpacker)
    assert fileresult.labels == set()
    upfiles = fileresult.unpackedfiles
    assert len(upfiles) == 5
    assert upfiles[0]['offset'] == 2
    assert upfiles[0]['size'] == 5
    assert upfiles[1]['offset'] == 9
    assert upfiles[1]['size'] == 5
    assert upfiles[2]['offset'] == 0
    assert upfiles[2]['size'] == 2
    assert upfiles[3]['offset'] == 7
    assert upfiles[3]['size'] == 2
    assert upfiles[4]['offset'] == 9+5
    assert upfiles[4]['size'] == len(s) - (9+5)

def test_carving_nothing_unpacks(scan_environment):
    s = b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    scanjob.carve_file_data(unpacker)
    assert fileresult.labels == set()
    upfiles = fileresult.unpackedfiles
    assert len(upfiles) == 0

def test_carving_all_unpacked(scan_environment):
    s = b'xBBxx'
    fn = pathlib.Path('test_unpack2.data')
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, s)
    scan_environment.set_unpackparsers([parser_fail_BB_1, parser_pass_BB_1_5])
    scanjob, unpacker = initialize_scanjob_and_unpacker(scan_environment, fileresult)

    scanjob.check_for_signatures(unpacker)
    scanjob.carve_file_data(unpacker)
    assert fileresult.labels == set()
    upfiles = fileresult.unpackedfiles
    assert len(upfiles) == 1



# test carving:

# 1. file that unpacks by extension but filesize is not the entire file
#    the remainder of the file is then scanned by signatures
#    ex: 2 .gbr files concatenated with extension .gbr
def test_file_with_extension_match_is_carved(scan_environment):
    fn = pathlib.Path("unpackers") / "combined" / "double-gimpbrush.gbr"
    fn_abs = testdata_dir / fn
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    assert len(scan_environment.resultqueue.queue) == 3
    result1 = scan_environment.resultqueue.get()
    result2 = scan_environment.resultqueue.get()
    result3 = scan_environment.resultqueue.get()
    assert result1.filename == fn_abs # parent file is absolute
    assert result2.filename.name == 'unpacked.gimpbrush' # relative
    assert result2.filename.parent.parent == pathlib.Path('.')
    assert result3.filename.name == 'unpacked.gimpbrush' # relative
    assert result3.filename.parent.parent == pathlib.Path('.')

# 2. ex: 2 .gbr files concatenated with extension .bla
def test_file_with_signature_match_is_carved(scan_environment):
    fn = pathlib.Path("unpackers") / "combined" / "double-gimpbrush.bla"
    fn_abs = testdata_dir / fn
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    assert len(scan_environment.resultqueue.queue) == 3
    result1 = scan_environment.resultqueue.get()
    result2 = scan_environment.resultqueue.get()
    result3 = scan_environment.resultqueue.get()
    # unpack file at root has absolute path
    assert result1.filename == fn_abs
    assert result2.filename.name == 'unpacked.gimpbrush'
    assert result2.filename.parent.parent == pathlib.Path('.')
    assert result3.filename.name == 'unpacked.gimpbrush'
    assert result3.filename.parent.parent == pathlib.Path('.')

# 3. ex: kernelconfig (featureless file) concatenated with .gif
def test_file_without_features_is_carved(scan_environment):
    fn = pathlib.Path("unpackers") / "combined" / "kernelconfig-gif.bla"
    fn_abs = testdata_dir / fn
    fileresult = FileResult(None, fn_abs, set())
    fileresult.set_filesize(fn_abs.stat().st_size)

    scanjob = ScanJob(fileresult)
    scan_environment.scanfilequeue.put(scanjob)
    try:
        processfile(MockDBConn(), MockDBCursor(), scan_environment)
    except QueueEmptyError:
        pass
    except ScanJobError as e:
        if e.e.__class__ != QueueEmptyError:
            raise e
    print(scan_environment.resultqueue.queue)
    assert len(scan_environment.resultqueue.queue) ==  3
    # assertlen(scan_environment.resultqueue.queue) == 4
    result1 = scan_environment.resultqueue.get()
    result2 = scan_environment.resultqueue.get()
    result3 = scan_environment.resultqueue.get()
    # result4 = scan_environment.resultqueue.get()
    # first result is for the file we queued and has an absolute path
    assert result1.filename == fn_abs
    # second result is the one matched by signature
    assert result2.filename.name == 'unpacked.gif'
    assert result2.filename.parent.parent == pathlib.Path('.')
    # third result is synthesized
    # gif_offset = 202554
    gif_offset = result1.unpackedfiles[0]['offset']
    assert result3.filename.name == \
            'unpacked-0x%x-0x%x' % (0,gif_offset-1)
    assert 'kernel configuration' in result3.labels
    # fourth result is a kernel config identified by featureless scan
    # featureless scan result is not extracted see TODO in ScanJob
    # assert result4.filename.name == 'kernelconfig'

# 4. Polyglot files


if __name__ == "__main__":
    unittest.main()
