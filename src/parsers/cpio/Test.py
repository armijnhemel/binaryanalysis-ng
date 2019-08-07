import sys, os
_scriptdir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_scriptdir, '..','..','test'))
from TestUtil import *

from parsers.cpio.UnpackParser import CpioNewAsciiUnpackParser, \
    CpioNewCrcUnpackParser, CpioPortableAsciiUnpackParser

class TestCpioUnpackParser(TestBase):
    def test_load_cpio_file_new_ascii(self):
        rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-new.cpio'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = CpioNewAsciiUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        self.assertLessEqual(r['length'], filesize)
        extracted_fn = data_unpack_dir / 'test.sgi'
        self.assertEqual(r['filesandlabels'], [(str(extracted_fn), ['unpacked'])])
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertTrue(extracted_fn_abs.exists())

    def test_load_cpio_file_portable_ascii(self):
        rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-old.cpio'
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = CpioPortableAsciiUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name+"-2")
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        self.assertLessEqual(r['length'], filesize)
        extracted_fn = data_unpack_dir / 'test.sgi'
        self.assertEqual(r['filesandlabels'], [(str(extracted_fn), ['unpacked'])])
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertTrue(extracted_fn_abs.exists())

# Following archive formats are supported: binary, old ASCII, new ASCII, crc, HPUX binary, HPUX old ASCII, old tar, and POSIX.1 tar.

if __name__ == '__main__':
    unittest.main()

