import sys, os
from test.TestUtil import *
from UnpackParserException import UnpackParserException

from .UnpackParser import GptPartitionTableUnpackParser

class TestGptPartitionTableUnpackParser(TestBase):
    def test_load_standard_file(self):
        rel_testfile = pathlib.Path('a') / 'OPNsense-18.1.6-OpenSSL-vga-amd64.img'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile,
                GptPartitionTableUnpackParser, 0,
                data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r['length'], self.get_testfile_size(rel_testfile))
        self.assertEqual(len(r['filesandlabels']), 4)

    def test_load_mbr_partition_table(self):
        rel_testfile = pathlib.Path('a') / \
            'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile,
                GptPartitionTableUnpackParser, 0,
                data_unpack_dir = data_unpack_dir)
        p.open()
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack()
        p.close()


if __name__ == '__main__':
    unittest.main()

