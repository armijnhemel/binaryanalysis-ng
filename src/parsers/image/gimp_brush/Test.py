import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GimpBrushUnpackParser

class TestGifUnpackParser(TestBase):
    def test_load_standard_gbr_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'gimpbrush' / 'test.gbr'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        p = GimpBrushUnpackParser(fileresult, self.scan_environment)
        p.open()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(r['filesandlabels'], [])
        self.assertEqual(r['metadata']['width'], 64)

if __name__ == '__main__':
    unittest.main()

