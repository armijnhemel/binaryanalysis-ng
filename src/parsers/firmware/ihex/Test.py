import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import IhexUnpackParser

class TestIhexUnpackParser(TestBase):
    def test_load_ihex_file_with_extension(self):
        rel_testfile = pathlib.Path('unpackers') / 'ihex' / 'example.hex'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, IhexUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r.get_length(), self.get_testfile_size(rel_testfile))
        self.assertEqual(len(r.get_unpacked_files()), 1)
        extracted_fn = r.get_unpacked_files()[0][0]
        self.assertEqual(str(extracted_fn), str(data_unpack_dir / 'example'))
        self.assertUnpackedPathExists(data_unpack_dir / 'example')

    def test_load_ihex_file_without_extension(self):
        rel_testfile = pathlib.Path('unpackers') / 'ihex' / 'example.txt'
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, IhexUnpackParser,
                0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r.get_length(), self.get_testfile_size(rel_testfile))
        self.assertEqual(len(r.get_unpacked_files()), 1)
        extracted_fn = r.get_unpacked_files()[0][0]
        self.assertEqual(str(extracted_fn),
                str(data_unpack_dir / 'unpacked-from-ihex'))
        self.assertUnpackedPathExists(data_unpack_dir / 'unpacked-from-ihex')


if __name__ == '__main__':
    unittest.main()

