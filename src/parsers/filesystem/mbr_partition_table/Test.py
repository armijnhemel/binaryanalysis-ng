import sys, os
from test.TestUtil import *
from UnpackParserException import UnpackParserException

from .UnpackParser import MbrPartitionTableUnpackParser

class TestMbrPartitionTableUnpackParser(TestBase):
    def test_load_standard_file(self):
        rel_testfile = pathlib.Path('a') / \
            'openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        p = MbrPartitionTableUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        self.assertEqual(r['length'], filesize)
        self.assertEqual(len(r['filesandlabels']), 4)

    def test_load_fat_partition(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        p = MbrPartitionTableUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        with self.assertRaisesRegex(UnpackParserException, r"no partitions") as cm:
            r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                    data_unpack_dir)


if __name__ == '__main__':
    unittest.main()

