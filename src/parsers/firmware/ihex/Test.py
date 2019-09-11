import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import IhexUnpackParser

class TestIhexUnpackParser(TestBase):
    def test_load_ihex_file_with_extension(self):
        rel_testfile = pathlib.Path('unpackers') / 'ihex' / 'example.hex'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        p = IhexUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(len(r['filesandlabels']), 1)
        extracted_fn = r['filesandlabels'][0][0]
        self.assertEqual(str(extracted_fn), str(data_unpack_dir / 'example'))
        self.assertUnpackedPathExists(data_unpack_dir / 'example')

    def test_load_ihex_file_without_extension(self):
        rel_testfile = pathlib.Path('unpackers') / 'ihex' / 'example.txt'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        p = IhexUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(len(r['filesandlabels']), 1)
        extracted_fn = r['filesandlabels'][0][0]
        self.assertEqual(str(extracted_fn),
                str(data_unpack_dir / 'unpacked-from-ihex'))
        self.assertUnpackedPathExists(data_unpack_dir / 'unpacked-from-ihex')


if __name__ == '__main__':
    unittest.main()

