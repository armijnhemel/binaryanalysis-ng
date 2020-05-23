import sys, os
from test.TestUtil import *

from .UnpackParser import IcoUnpackParser

class TestIcoUnpackParser(TestBase):
    def test_load_standard_ico_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'ico' / 'test.ico'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = IcoUnpackParser(fileresult, self.scan_environment, data_unpack_dir,
                0)
        p.open()
        # dummy data unpack dir
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(r['filesandlabels'], [])

if __name__ == '__main__':
    unittest.main()

