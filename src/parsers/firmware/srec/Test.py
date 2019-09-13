import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import SrecUnpackParser

class TestSrecUnpackParser(TestBase):
    def test_load_srec_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'srec' / 'helloworld.srec'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = SrecUnpackParser(fileresult, self.scan_environment, data_unpack_dir,
                0)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(r['filesandlabels'], [])
        # TODO: fix assertions

if __name__ == '__main__':
    unittest.main()

