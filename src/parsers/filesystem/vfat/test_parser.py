import sys, os
import hashlib
from test.util import *
from test.mock_metadirectory import *

from .UnpackParser import VfatUnpackParser

def test_fat12_single_file_unpacked_correctly(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
    # rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-b24.fat'
    # rel_testfile = pathlib.Path('a') / 'unpacked.mbr-partition0.part'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = VfatUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() == filesize
    assert len(r.get_unpacked_files()) == 1
    unpacked_path_rel = data_unpack_dir / 'hellofat.txt'
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assert r.get_unpacked_files()[0].filename == unpacked_path_rel
    assertUnpackedPathExists(scan_environment, unpacked_path_rel)
    with open(unpacked_path_abs,"rb") as f:
        assert f.read() == b'hello fat\n'

def test_fat12_single_file_unpacked_correctly_with_offset(scan_environment):
    padding_length = 5
    orig_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'prepend-test.fat'
    abs_orig_testfile = testdir_base / 'testdata' / orig_testfile
    abs_testfile = testdir_base / 'testdata' / rel_testfile
    with open(abs_testfile,"wb") as f:
        f.write(b"A" * padding_length)
        with open(abs_orig_testfile,"rb") as g:
                f.write(g.read())
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = VfatUnpackParser(fr, scan_environment, data_unpack_dir, padding_length)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() == filesize - padding_length
    assert len(r.get_unpacked_files()) == 1
    unpacked_path_rel = data_unpack_dir / 'hellofat.txt'
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assert r.get_unpacked_files()[0].filename == unpacked_path_rel
    assertUnpackedPathExists(scan_environment, unpacked_path_rel)
    with open(unpacked_path_abs,"rb") as f:
        assert f.read() == b'hello fat\n'


# test if extraction of file of multiple blocks went ok
def test_fat12_multiple_blocks_unpacked_correctly(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = VfatUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    unpacked_path_rel = data_unpack_dir / 'copying'
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assertUnpackedPathExists(scan_environment, unpacked_path_rel)
    with open(unpacked_path_abs,"rb") as f:
        m = hashlib.md5()
        m.update(f.read())
        # compare to md5 hash of /usr/share/licenses/glibc/COPYING
        assert m.hexdigest() == 'b234ee4d69f5fce4486a80fdaf4a4263'

# test if extraction of (nested) subdirectories went ok
def test_fat12_subdirectories_unpacked_correctly(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = VfatUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert len(r.get_unpacked_files()) == 4

    unpacked_path_rel = data_unpack_dir / 'subdir1.dir'
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assertUnpackedPathExists(scan_environment, unpacked_path_rel)
    assert unpacked_path_abs.is_dir()

    unpacked_path_rel = data_unpack_dir / 'subdir2.dir' / 'subdir2a.dir'
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assertUnpackedPathExists(scan_environment, unpacked_path_rel)
    assert unpacked_path_abs.is_dir()

    unpacked_path_rel = data_unpack_dir / 'subdir2.dir' / 'subdir2a.dir' / 'license'
    unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
    assertUnpackedPathExists(scan_environment, unpacked_path_rel)

# test FAT12, FAT16, FAT32
# test LFN (long filenames)

