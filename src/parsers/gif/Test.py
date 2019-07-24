import sys, os
_scriptdir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_scriptdir, '..','..','test'))
# import unittest
from TestUtil import *

from Parser import GifParser
from ParserException import ParserException


class TestGifParser(TestBase):
    def test_load_standard_gif_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test.gif'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = GifParser()
        # dummy data unpack dir
        data_unpack_dir = self.unpackdir / rel_testfile.parent
        print(data_unpack_dir)
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        print(r)
        print(dir(p.data))
        self.assertEqual(p.data.logical_screen.image_width, 3024)
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(r['filesandlabels'], [])

    def test_gif_file_is_extracted(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test-prepend-random-data.gif'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = GifParser()
        data_unpack_dir = self.unpackdir / rel_testfile.parent
        print(data_unpack_dir)
        r = p.parse_and_unpack(fileresult, self.scan_environment, 128,
                data_unpack_dir)
        # check if file exists
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], 7073713)
        print(self.fileresult)
        print(r['filesandlabels'])
        #self.assertTrue(os.path.exists
        self.assertEqual(p.data.logical_screen.image_width, 3024)

    def test_load_png_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'png' / 'test.png'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        # with self.assertRaises(ParserException) as context:
        #    p = GifParser()
        #    p.parse_and_unpack(fileresult, self.scan_environment, 0, self.unpackdir)
        p = GifParser()
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0, self.unpackdir)
        self.assertFalse(r['status'])
        self.assertIsNotNone(r['error']['reason'])

if __name__ == '__main__':
    unittest.main()

