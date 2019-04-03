from TestUtil import *

class TestFileResult(TestBase):
    def test_fileresult_has_correct_filenames(self):
        relative_path = pathlib.Path("a/b/c.txt")
        full_path = pathlib.Path(self.unpackdir) / relative_path
        fr = create_fileresult_for_path(self.unpackdir, relative_path, calculate_size=False)
        d = fr.get()
        self.assertEqual(fr.parent, str(relative_path.parent))
        # self.assertEqual(fr.relpath, relative_path)
        self.assertEqual(fr.filename, relative_path)
        # self.assertEqual(d['fullfilename'], str(full_path))
        self.assertEqual(d['filename'], str(relative_path))
        self.assertEqual(d['parent'], str(relative_path.parent))


if __name__=="__main__":
    unittest.main()
