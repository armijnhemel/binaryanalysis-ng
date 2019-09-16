import sys, os
from test.TestUtil import *

from .UnpackParser import CpioNewAsciiUnpackParser, \
    CpioNewCrcUnpackParser, CpioPortableAsciiUnpackParser, \
    rewrite_symlink

class TestCpioUnpackParser(TestBase):
    def test_load_cpio_file_new_ascii(self):
        rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-new.cpio'
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
        p = self.create_unpackparser_for_path(rel_testfile,
                CpioNewAsciiUnpackParser, 0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertLessEqual(r['length'], self.get_testfile_size(rel_testfile))
        extracted_fn = data_unpack_dir / 'test.sgi'
        self.assertEqual(r['filesandlabels'], [(str(extracted_fn), ['unpacked'])])
        self.assertUnpackedPathExists(extracted_fn)

    def test_load_cpio_file_portable_ascii(self):
        rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-old.cpio'
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-2")
        p = self.create_unpackparser_for_path(rel_testfile,
                CpioPortableAsciiUnpackParser, 0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertLessEqual(r['length'], self.get_testfile_size(rel_testfile))
        extracted_fn = data_unpack_dir / 'test.sgi'
        self.assertEqual(r['filesandlabels'], [(str(extracted_fn), ['unpacked'])])
        self.assertUnpackedPathExists(extracted_fn)

    def test_unpack_different_filetypes(self):
        # test file from kr105_ps4kerneltest.zip
        rel_testfile = pathlib.Path('a') / 'initramfs.cpio'
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-3")
        p = self.create_unpackparser_for_path(rel_testfile,
                CpioNewAsciiUnpackParser, 0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertLessEqual(r['length'], self.get_testfile_size(rel_testfile))

        # check if etc is a directory
        extracted_fn = data_unpack_dir / 'etc'
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertTrue(extracted_fn_abs.is_dir())
        extracted_labels = [ i for i in r['filesandlabels'] if i[0] ==
                str(extracted_fn)][0][1]
        self.assertEqual(extracted_labels, ['unpacked'])

        # check if bin/dhclient is a symlink
        extracted_fn = data_unpack_dir / 'bin' / 'dbclient'
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertTrue(extracted_fn_abs.is_symlink())
        self.assertEqual(extracted_fn_abs.resolve().name, 'dropbearmulti')
        extracted_labels = [ i for i in r['filesandlabels'] if i[0] ==
                str(extracted_fn)][0][1]
        self.assertIn('symbolic link', extracted_labels)

        # check if device /dev/zero is skipped
        extracted_fn = data_unpack_dir / 'dev' / 'zero'
        self.assertUnpackedPathDoesNotExist(extracted_fn)
        extracted_files_and_labels = [ i for i in r['filesandlabels'] if i[0] ==
                str(extracted_fn)]
        self.assertEqual(extracted_files_and_labels, [])

    def test_cpio_with_absolute_path(self):
        rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-absolute-path.cpio'
        data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-4")
        p = self.create_unpackparser_for_path(rel_testfile,
                CpioNewAsciiUnpackParser, 0, data_unpack_dir = data_unpack_dir)
        p.open()
        r = p.parse_and_unpack()
        p.close()
        self.assertLessEqual(r['length'], self.get_testfile_size(rel_testfile))

        extracted_fn = data_unpack_dir / 'e' / 't.sgi'
        self.assertUnpackedPathExists(extracted_fn)
        extracted_labels = [ i for i in r['filesandlabels'] if i[0] ==
                str(extracted_fn)][0][1]
        self.assertEqual(extracted_labels, ['unpacked'])

    def test_rewrite_symlink(self):
        p = CpioNewAsciiUnpackParser(None, None, None, 0)

        expected_results = [
            ('test/dir/a.txt', '../c.txt', '../c.txt'),
            ('test/dir/a.txt', '../../c.txt', '../../c.txt'),
            ('test/dir/a.txt', '../../../../../../../../../c.txt', '../../c.txt'),
            ('/test/dir/a.txt', '../../../../../../../../../c.txt', '../../c.txt'),
            ('test/dir/a.txt', '/a/b/c.txt', '../../a/b/c.txt'),
            ('test/dir/a.txt', '/a/../b/c.txt', '../../b/c.txt'),
            ('test/dir/a.txt', '/a/../../../b/c.txt', '../../b/c.txt'),
            ('/some/test/dir/a.txt', '/a/b/c.txt', '../../../a/b/c.txt'),
        ]
        for filename, target, expected_link in expected_results:
            ptarget = pathlib.Path(target)
            pfile = pathlib.Path(filename)
            plink = pathlib.Path(expected_link)
            self.assertEqual(rewrite_symlink(pfile, ptarget), plink)


# Following archive formats are supported: binary, old ASCII, new ASCII, crc, HPUX binary, HPUX old ASCII, old tar, and POSIX.1 tar.

if __name__ == '__main__':
    unittest.main()

