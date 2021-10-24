import sys, os
from test.util import *
from test.mock_metadirectory import *
from UnpackParserException import UnpackParserException

from .UnpackParser import MbrPartitionTableUnpackParser

def test_load_standard_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'download' / 'filesystem' / 'mbr_partition_table' / 'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = MbrPartitionTableUnpackParser(f, 0, sz)
        p.parse_from_offset()
        p.write_info(md)
        for _ in p.unpack(md): pass
    assert len(md.unpacked_files) == 4

def test_load_fat_partition(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'fat' / 'test.fat'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = MbrPartitionTableUnpackParser(f, 0, sz)
        with pytest.raises(UnpackParserException, match=r"no partitions") as cm:
            p.parse_from_offset()
            p.write_info(md)
            for _ in p.unpack(md): pass

# TODO: MBR is included in GPT, therefore MBR parsing may work. Best to combine the
# two parsers into one.
def test_load_gpt_partition_table(scan_environment):
    testfile = testdir_base / 'testdata' / 'download' / 'filesystem' / 'gpt_partition_table' / 'OPNsense-21.7.1-OpenSSL-vga-amd64.img'
    sz = testfile.stat().st_size
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with testfile.open('rb') as f:
        p = MbrPartitionTableUnpackParser(f, 0, sz)
        with pytest.raises(UnpackParserException, match = r"partition bigger than file") as cm:
            p.parse_from_offset()
            p.write_info(md)
            for _ in p.unpack(md): pass

