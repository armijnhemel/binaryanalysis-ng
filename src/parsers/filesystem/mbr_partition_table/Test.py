import sys, os
from test.TestUtil import *
from UnpackParserException import UnpackParserException

from .UnpackParser import MbrPartitionTableUnpackParser

class TestMbrPartitionTableUnpackParser(TestBase):
    def test_load_standard_file(self):
        rel_testfile = pathlib.Path('a') / \
            'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
        p = self.create_unpackparser_for_path(rel_testfile,
                MbrPartitionTableUnpackParser, 0)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], self.get_testfile_size(rel_testfile))
        self.assertEqual(len(r['filesandlabels']), 4)

    def test_load_fat_partition(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
        p = self.create_unpackparser_for_path(rel_testfile,
                MbrPartitionTableUnpackParser, 0)
        p.open()
        with self.assertRaisesRegex(UnpackParserException, r"no partitions") as cm:
            r = p.parse_and_unpack()
        p.close()

if __name__ == '__main__':
    unittest.main()

