import sys, os
_scriptdir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_scriptdir, '..','..','test'))
from TestUtil import *

from parsers.vfat.UnpackParser import VfatUnpackParser

class TestVfatUnpackParser(TestBase):
    def test_fat12(self):
        rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test.fat'
        # rel_testfile = pathlib.Path('unpackers') / 'fat' / 'test-b24.fat'
        rel_testfile = pathlib.Path('a') / 'unpacked.mbr-partition0.part'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = VfatUnpackParser()
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        self.assertEqual(r['length'], filesize)
        self.assertEqual(len(r['filesandlabels']), 4)

    # test if extraction of file of multiple blocks went ok
    # test if extraction of (nested) subdirectories went ok
    # test FAT12, FAT16, FAT32
    # test LFN (long filenames)

if __name__ == '__main__':
    unittest.main()

