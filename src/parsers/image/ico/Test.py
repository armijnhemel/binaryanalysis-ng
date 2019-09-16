import sys, os
from test.TestUtil import *

from .UnpackParser import IcoUnpackParser

class TestIcoUnpackParser(TestBase):
    def test_load_standard_ico_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'ico' / 'test.ico'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, IcoUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r['length'], self.get_testfile_size(rel_testfile))
        self.assertEqual(r['filesandlabels'], [])

if __name__ == '__main__':
    unittest.main()

