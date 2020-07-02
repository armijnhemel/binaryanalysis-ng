import sys, os
from test.util import *
from UnpackParserException import UnpackParserException

from .UnpackParser import MbrPartitionTableUnpackParser

def test_load_standard_file(scan_environment):
    rel_testfile = pathlib.Path('a') / \
        'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = MbrPartitionTableUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r['status']
    assert r['length'] == filesize
    assert len(r['filesandlabels']) == 4

def test_load_fat_partition(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = MbrPartitionTableUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException, match=r"no partitions") as cm:
        r = p.parse_and_unpack()
    p.close()

