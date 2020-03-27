import sys, os
from test.TestUtil import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GifUnpackParser

class TestGifUnpackParser(TestBase):
    def test_load_standard_gif_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test.gif'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = GifUnpackParser(fileresult, self.scan_environment, data_unpack_dir,
                0)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(r['filesandlabels'], [])
        self.assertEqual(r['metadata']['width'], 3024)

    def test_extracted_gif_file_is_correct(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test-prepend-random-data.gif'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        filesize = fileresult.filesize
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = GifUnpackParser(fileresult, self.scan_environment, data_unpack_dir,
                128)
        p.open()
        r = p.parse_and_unpack()
        p.carve()
        p.close()
        self.assertTrue(r['status'])
        self.assertEqual(r['length'], 7073713)
        unpacked_file = r['filesandlabels'][0][0]
        unpacked_labels = r['filesandlabels'][0][1]
        self.assertEqual(pathlib.Path(unpacked_file),
                pathlib.Path(data_unpack_dir) / 'unpacked.gif')
        self.assertUnpackedPathExists(unpacked_file)
        self.assertEqual((self.unpackdir / unpacked_file).stat().st_size, r['length'])
        self.assertEqual(r['metadata']['width'], 3024)
        self.assertSetEqual(set(unpacked_labels),
                set(r['labels'] + ['unpacked']))

    def test_load_png_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'png' / 'test.png'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        data_unpack_dir = rel_testfile.parent / 'some_dir'
        p = GifUnpackParser(fileresult, self.scan_environment, data_unpack_dir,
                0)
        p.open()
        with self.assertRaisesRegex(UnpackParserException, r".*") as cm:
            r = p.parse_and_unpack()
        p.close()

if __name__ == '__main__':
    unittest.main()

