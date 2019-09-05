import sys, os
import hashlib
_scriptdir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_scriptdir, '..','..','test'))
from TestUtil import *

from parsers.vfat.UnpackParser import VfatUnpackParser

class TestVfatUnpackParser(TestBase):
    def test_fat12_single_file_unpacked_correctly(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
        # rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-b24.fat'
        # rel_testfile = pathlib.Path('a') / 'unpacked.mbr-partition0.part'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = VfatUnpackParser()
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        self.assertEqual(r['length'], filesize)
        self.assertEqual(len(r['filesandlabels']), 1)
        unpacked_path_rel = data_unpack_dir / 'hellofat.txt'
        unpacked_path_abs = self.unpackdir / unpacked_path_rel
        self.assertEqual(r['filesandlabels'][0][0], unpacked_path_rel)
        self.assertTrue(unpacked_path_abs.exists())
        with open(unpacked_path_abs,"rb") as f:
            self.assertEqual(f.read(), b'hello fat\n')

    # test if extraction of file of multiple blocks went ok
    def test_fat12_multiple_blocks_unpacked_correctly(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = VfatUnpackParser()
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        unpacked_path_rel = data_unpack_dir / 'copying'
        unpacked_path_abs = self.unpackdir / unpacked_path_rel
        self.assertTrue(unpacked_path_abs.exists())
        with open(unpacked_path_abs,"rb") as f:
            m = hashlib.md5()
            m.update(f.read())
            # compare to md5 hash of /usr/share/licenses/glibc/COPYING
            self.assertEqual(m.hexdigest(), 'b234ee4d69f5fce4486a80fdaf4a4263')

    def test_fat12_subdirectories_unpacked_correctly(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-fat12-multidirfile.fat'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = VfatUnpackParser()
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))

        unpacked_path_rel = data_unpack_dir / 'subdir1.dir'
        unpacked_path_abs = self.unpackdir / unpacked_path_rel
        self.assertTrue(unpacked_path_abs.exists())
        self.assertTrue(unpacked_path_abs.is_dir())

        unpacked_path_rel = data_unpack_dir / 'subdir2.dir' / 'subdir2a.dir'
        unpacked_path_abs = self.unpackdir / unpacked_path_rel
        self.assertTrue(unpacked_path_abs.exists())
        self.assertTrue(unpacked_path_abs.is_dir())

        unpacked_path_rel = data_unpack_dir / 'subdir2.dir' / 'subdir2a.dir' / 'LICENSE'
        unpacked_path_abs = self.unpackdir / unpacked_path_rel
        self.assertTrue(unpacked_path_abs.exists())
        self.assertTrue(unpacked_path_abs.is_dir())

    # test if extraction of (nested) subdirectories went ok
    # test FAT12, FAT16, FAT32
    # test LFN (long filenames)

if __name__ == '__main__':
    unittest.main()

