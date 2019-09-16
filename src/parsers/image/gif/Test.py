import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GifUnpackParser

class TestGifUnpackParser(TestBase):
    def test_load_standard_gif_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test.gif'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        p = self.create_unpackparser_for_path(rel_testfile, GifUnpackParser, 0)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertEqual(r.get_length(), self.get_testfile_size(rel_testfile))
        self.assertEqual(r.get_unpacked_files(), [])
        self.assertEqual(r.get_metadata()['width'], 3024)

    def test_extracted_gif_file_is_correct(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test-prepend-random-data.gif'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = self.create_unpackparser_for_path(rel_testfile, GifUnpackParser,
                128, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.carve()
        p.close()
        self.assertEqual(r.get_length(), 7073713)
        unpacked_file = r.get_unpacked_files()[0][0]
        unpacked_labels = r.get_unpacked_files()[0][1]
        self.assertEqual(pathlib.Path(unpacked_file),
                pathlib.Path(data_unpack_dir) / 'unpacked.gif')
        self.assertUnpackedPathExists(unpacked_file)
        self.assertEqual((self.unpackdir / unpacked_file).stat().st_size, r.get_length())
        self.assertEqual(r.get_metadata()['width'], 3024)
        self.assertSetEqual(set(unpacked_labels),
                set(r.get_labels() + ['unpacked']))

    def test_load_png_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'png' / 'test.png'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        p = self.create_unpackparser_for_path(rel_testfile, GifUnpackParser, 0)
        p.open()
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack()
        p.close()

if __name__ == '__main__':
    unittest.main()

