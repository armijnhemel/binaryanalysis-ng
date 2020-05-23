import sys, os
from test.TestUtil import *
from UnpackParserException import UnpackParserException

from .UnpackParser import TarUnpackParser

class TestCpioUnpackParser(TestBase):
    def test_load_tar_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'tar'/ 'test.tar'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
        p = TarUnpackParser(fileresult, self.scan_environment, data_unpack_dir, 0)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        extracted_fn = data_unpack_dir / 'test.sgi'
        self.assertEqual(r['filesandlabels'], [ (str(extracted_fn), []) ])

    def test_load_tar_file_absolute(self):
        rel_testfile = pathlib.Path('unpackers') / 'tar'/ 'tar-abs.tar'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
        p = TarUnpackParser(fileresult, self.scan_environment, data_unpack_dir, 0)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertTrue(r['status'])
        extracted_fn = "/tmp/test.sgi"
        self.assertEqual(r['filesandlabels'][0], (str(extracted_fn), []))
        # TODO: check where file is extracted


    def test_invalid_file_not_tar(self):
        rel_testfile = pathlib.Path('unpackers') / 'gif'/ 'test.gif'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set())
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
        p = TarUnpackParser(fileresult, self.scan_environment, data_unpack_dir, 0)
        p.open()
        with self.assertRaises(UnpackParserException):
            r = p.parse_and_unpack()
        p.close()
      
    if __name__ == '__main__':
        unittest.main()

