import sys, os
from test.util import *
from test.mock_metadirectory import *

from .UnpackParser import GptPartitionTableUnpackParser

def test_load_standard_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'download' / 'filesystem' / 'gpt_partition_table' / 'OPNsense-21.7.1-OpenSSL-vga-amd64.img'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GptPartitionTableUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open(open_file=False) as unpacked_md:
        assert len(unpacked_md.unpacked_files) == 4

def test_load_mbr_partition_table(scan_environment):
    testfile = testdir_base / 'testdata' / 'download' / 'filesystem' / 'mbr_partition_table' / 'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = GptPartitionTableUnpackParser(opened_md, 0)
        with pytest.raises(UnpackParserException, match = r".*") as cm:
            p.parse_from_offset()
            p.write_info(opened_md)
            for _ in p.unpack(opened_md): pass



