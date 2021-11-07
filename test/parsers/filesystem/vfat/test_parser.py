import sys, os
import hashlib
from util import *
from mock_metadirectory import *

from bang.parsers.filesystem.vfat.UnpackParser import VfatUnpackParser

def test_fat12_single_file_unpacked_correctly(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test.fat'
    # rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-b24.fat'
    # rel_testfile = pathlib.Path('a') / 'unpacked.mbr-partition0.part'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = VfatUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert len(unpacked_md.unpacked_files) == 1
        assert list(unpacked_md.unpacked_files.keys()) == [ unpacked_md.unpacked_path(pathlib.Path('hellofat.txt')) ]
        extracted_path = scan_environment.unpackdirectory / list(unpacked_md.unpacked_files.keys())[0]
        with extracted_path.open('rb') as f:
            assert f.read() == b'hello fat\n'

# test if extraction of file of multiple blocks went ok
def test_fat12_multiple_blocks_unpacked_correctly(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = VfatUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        unpacked_path = unpacked_md.unpacked_path(pathlib.Path('copying'))
        assert unpacked_path in unpacked_md.unpacked_files
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path
        with open(unpacked_path_abs, 'rb') as f:
            m = hashlib.md5()
            m.update(f.read())
            # compare to md5 hash of /usr/share/licenses/glibc/COPYING
            assert m.hexdigest() == 'b234ee4d69f5fce4486a80fdaf4a4263'


# test if extraction of (nested) subdirectories went ok
def test_fat12_subdirectories_unpacked_correctly(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test-fat12-multidirfile.fat'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = VfatUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:

        assert len(unpacked_md.unpacked_files) == 4

        unpacked_path_rel = unpacked_md.unpacked_path(pathlib.Path('subdir1.dir'))
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
        assert unpacked_path_abs.is_dir()

        unpacked_path_rel = unpacked_md.unpacked_path(pathlib.Path('subdir2.dir') / 'subdir2a.dir')
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
        assert unpacked_path_abs.is_dir()

        unpacked_path_rel = unpacked_md.unpacked_path(pathlib.Path('subdir2.dir') / 'subdir2a.dir' / 'license')
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
        assert unpacked_path_abs.exists()


def test_fat_with_volume_name(scan_environment):
    # test file: partition 0 of download/filesystem/gpt_partition_table/OPNsense-21.7.1-OpenSSL-vga-amd64.img
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'unpacked.gpt-partition0.part'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = VfatUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:

        assert len(unpacked_md.unpacked_files) == 2

        unpacked_path_rel = unpacked_md.unpacked_path(pathlib.Path('efi/boot/startup.nsh'))
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
        assert unpacked_path_abs.exists()

        unpacked_path_rel = unpacked_md.unpacked_path(pathlib.Path('efi/boot/BOOTx64.efi'))
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
        assert unpacked_path_abs.exists()

        # TODO: volume name should not be unpacked
        unpacked_path_rel = unpacked_md.unpacked_path(pathlib.Path('efisys'))
        unpacked_path_abs = scan_environment.unpackdirectory / unpacked_path_rel
        assert not unpacked_path_abs.exists()


# TODO: test all of FAT12, FAT16, FAT32
# TODO: test LFN (long filenames)

