import sys, os
import hashlib
from test.util import *
from test.mock_metadirectory import *

from .UnpackParser import VfatUnpackParser

def test_fat12_single_file_unpacked_correctly(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test.fat'
    # rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-b24.fat'
    # rel_testfile = pathlib.Path('a') / 'unpacked.mbr-partition0.part'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = VfatUnpackParser(f, 0, sz)
        p.parse_from_offset()
        p.write_info(md)
        for _ in p.unpack(md): pass
    assert len(md.unpacked_files) == 1
    assert list(md.unpacked_files.keys()) == [ md.unpacked_path(pathlib.Path('hellofat.txt')) ]
    extracted_path = scan_environment.unpackdirectory / list(md.unpacked_files.keys())[0]
    with extracted_path.open('rb') as f:
        assert f.read() == b'hello fat\n'

# test if extraction of file of multiple blocks went ok
def test_fat12_multiple_blocks_unpacked_correctly(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = VfatUnpackParser(f, 0, sz)
        p.parse_from_offset()
        p.write_info(md)
        for _ in p.unpack(md): pass
    unpacked_path = md.unpacked_path(pathlib.Path('copying'))
    assert unpacked_path in md.unpacked_files
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path
    with open(unpacked_path_abs, 'rb') as f:
        m = hashlib.md5()
        m.update(f.read())
        # compare to md5 hash of /usr/share/licenses/glibc/COPYING
        assert m.hexdigest() == 'b234ee4d69f5fce4486a80fdaf4a4263'


# test if extraction of (nested) subdirectories went ok
def test_fat12_subdirectories_unpacked_correctly(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = VfatUnpackParser(f, 0, sz)
        p.parse_from_offset()
        p.write_info(md)
        for _ in p.unpack(md): pass

    assert len(md.unpacked_files) == 4

    unpacked_path_rel = md.unpacked_path(pathlib.Path('subdir1.dir'))
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assert unpacked_path_abs.is_dir()

    unpacked_path_rel = md.unpacked_path(pathlib.Path('subdir2.dir') / 'subdir2a.dir')
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assert unpacked_path_abs.is_dir()

    unpacked_path_rel = md.unpacked_path(pathlib.Path('subdir2.dir') / 'subdir2a.dir' / 'license')
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assert unpacked_path_abs.exists()

# test FAT12, FAT16, FAT32
# test LFN (long filenames)

