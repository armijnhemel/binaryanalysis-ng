import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GimpBrushUnpackParser

class TestGimpBrushUnpackParser(TestBase):
    def test_load_standard_gbr_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'gimpbrush' / 'test.gbr'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile,
                GimpBrushUnpackParser, 0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r['length'], self.get_testfile_size(rel_testfile))
        self.assertEqual(r['filesandlabels'], [])
        self.assertEqual(r['metadata']['width'], 64)

    def test_load_offset_gbr_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'gimpbrush' / 'test-prepend-random-data.gbr'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        offset = 128
        p = self.create_unpackparser_for_path(rel_testfile,
                GimpBrushUnpackParser, offset,
                data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r['length'], self.get_testfile_size(rel_testfile) - offset)
        self.assertEqual(r['filesandlabels'], [])
        self.assertEqual(r['metadata']['width'], 64)

if __name__ == '__main__':
    unittest.main()

