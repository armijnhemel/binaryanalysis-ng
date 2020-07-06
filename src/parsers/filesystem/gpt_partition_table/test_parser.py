import sys, os
from test.util import *

from .UnpackParser import GptPartitionTableUnpackParser

def test_load_standard_file(scan_environment):
    rel_testfile = pathlib.Path('download') / 'filesystem' / 'gpt_partition_table' / 'OPNsense-18.1.6-OpenSSL-vga-amd64.img'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GptPartitionTableUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() == filesize
    assert len(r.get_unpacked_files()) == 4

def test_load_mbr_partition_table(scan_environment):
    rel_testfile = pathlib.Path('download') / 'filesystem' / 'mbr_partition_table' / 'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    p = GptPartitionTableUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException, match = r".*") as cm:
        r = p.parse_and_unpack()
    p.close()


