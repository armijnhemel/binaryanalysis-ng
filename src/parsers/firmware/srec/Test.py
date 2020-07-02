import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import SrecUnpackParser

class TestSrecUnpackParser(TestBase):
    def test_load_srec_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'srec' / 'helloworld.srec'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, SrecUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r.get_length(), self.get_testfile_size())
        self.assertEqual(r.get_unpacked_files(), [])
        # TODO: fix assertions

if __name__ == '__main__':
    unittest.main()

