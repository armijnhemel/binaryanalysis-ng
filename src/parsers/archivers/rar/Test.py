import sys, os
from test.TestUtil import *

from .UnpackParser import RarUnpackParser

class TestRarUnpackParser(TestBase):
    def test_load_standard_file(self):
        rel_testfile = pathlib.Path('a') / 'hachoir-core.rar'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, RarUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], self.get_testfile_size(rel_testfile))
        self.assertEqual(len(r['filesandlabels']), 0)

if __name__ == '__main__':
    unittest.main()

