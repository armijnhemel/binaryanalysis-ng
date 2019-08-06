import sys, os
_scriptdir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_scriptdir, '..','..','test'))
from TestUtil import *

from parsers.cpio.UnpackParser import CpioUnpackParser

class TestCpioUnpackParser(TestBase):
    def test_load_standard_cpio_file(self):
        rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-new.cpio'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = CpioUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = (self.unpackdir / rel_testfile).parent
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r['error'])
        self.assertEqual(r['length'], filesize)
        self.assertEqual(r['filesandlabels'], [])
        self.assertEqual(r['metadata']['width'], 3024)

# Following archive formats are supported: binary, old ASCII, new ASCII, crc, HPUX binary, HPUX old ASCII, old tar, and POSIX.1 tar.

if __name__ == '__main__':
    unittest.main()

