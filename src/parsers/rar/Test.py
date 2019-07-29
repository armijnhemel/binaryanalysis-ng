import sys, os
_scriptdir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_scriptdir, '..','..','test'))
from TestUtil import *

from parsers.rar.UnpackParser import RarUnpackParser

class TestRarUnpackParser(TestBase):
    def test_load_standard_file(self):
        rel_testfile = pathlib.Path('a') / 'hachoir-core.rar'
        filename = pathlib.Path(self.testdata_dir) / rel_testfile
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile)
        filesize = fileresult.filesize
        p = RarUnpackParser()
        # dummy data unpack dir
        data_unpack_dir = (self.unpackdir / rel_testfile).parent
        r = p.parse_and_unpack(fileresult, self.scan_environment, 0,
                data_unpack_dir)
        self.assertTrue(r['status'], r.get('error'))
        self.assertEqual(r['length'], filesize)
        self.assertEqual(len(r['filesandlabels']), 0)

if __name__ == '__main__':
    unittest.main()

