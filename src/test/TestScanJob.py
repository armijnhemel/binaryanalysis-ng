import sys
import os
import shutil
import pathlib
import inspect
import unittest

from .TestUtil import *

from FileResult import *
from ScanJob import *
# from ScanEnvironment import *

# import bangfilescans

class TestScanJob(TestBase):

    def _make_directory_in_unpackdir(self, dirname):
        try:
            os.makedirs(os.path.join(self.unpackdir, dirname))
        except FileExistsError:
            pass

    def _create_padding_file_in_directory(self):
        self.parent_dir = pathlib.Path('a')
        self._make_directory_in_unpackdir(self.parent_dir)
        self.padding_file = self.parent_dir / 'PADDING-0x00-0x01'
        f = (self.unpackdir / self.padding_file).open('wb')
        f.write(b'\0' * 20)
        f.close()

    def _create_absolute_path_object(self, fn):
        return pathlib.Path(os.path.join(self.unpackdir, fn))

    def test_carved_padding_file_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = FileResult(self.padding_file, None, set(), set())
        fileresult.set_filesize(
                (self.unpackdir / self.padding_file).stat().st_size)
        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_unscannable_file()
        unpacker.append_unpacked_range(0, 5) # bytes [0:5) are unpacked
        scanjob.carve_file_data(unpacker)
        j = self.scanfile_queue.get()
        self.assertSetEqual(j.fileresult.labels, set(['padding', 'synthesized']))

    def test_process_paddingfile_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = FileResult(self.padding_file, None, set(), set(['padding']))
        fileresult.set_filesize(
                (self.unpackdir / self.padding_file).stat().st_size)
        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        result = self.result_queue.get()
        self.assertSetEqual(result.labels, set(['binary', 'padding']))

    def test_process_css_file_has_correct_labels(self):
        # /home/tim/bang-test-scrap/bang-scan-jucli3nm/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/www/luci-static/bootstrap/cascade.css
        fn = pathlib.Path("a/cascade.css")
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)
        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        result = self.result_queue.get()
        self.assertSetEqual(result.labels, set(['binary', 'css']))

    def test_openwrt_version_has_correct_labels(self):
        # openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/etc/openwrt_version
        fn = pathlib.Path("a/openwrt_version")
        fn_abs = self.testdata_dir / fn
        # self._copy_file_from_testdata(fn)
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as ex:
            if ex.e.__class__ != QueueEmptyError:
                raise ex
        result = self.result_queue.get()
        self.assertSetEqual(result.labels, set(['text', 'base64', 'urlsafe']))

    def test_dhcpv6sh_has_correct_labels(self):
        # /home/tim/bang-test-scrap/bang-scan-wd8il1i5/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/lib/netifd/proto/dhcpv6.sh
        fn = pathlib.Path("a/dhcpv6.sh")
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)
        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        result = self.result_queue.get()
        self.assertSetEqual(result.labels, set(['text', 'script', 'shell']))

    def test_kernelconfig_is_processed(self):
        rel_testfile = pathlib.Path('unpackers') / 'kernelconfig' / 'kernelconfig'
        abs_testfile = self.testdata_dir / rel_testfile
        fileresult = FileResult(abs_testfile, None, set(), set())
        fileresult.set_filesize(abs_testfile.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        result = self.result_queue.get()

        self.assertEqual(result.filename, abs_testfile)
        self.assertSetEqual(result.labels, set(['text', 'kernel configuration']))

    def test_gzip_unpacks_to_right_directory(self):
        fn = pathlib.Path("a") / "hello.gz"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        result1 = self.result_queue.get()
        result2 = self.result_queue.get()
        fn_expected = pathlib.Path(fn.name+'-0x00000000-gzip-1') / 'hello'
        self.assertEqual(result2.filename, fn_expected)

    def test_report_has_correct_path(self):
        fn = pathlib.Path("a") / "hello.gz"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        result1 = self.result_queue.get()
        result2 = self.result_queue.get()
        unpack_report = result1.unpackedfiles[0]
        fn_expected = pathlib.Path(fn.name+'-0x00000000-gzip-1') / 'hello'

        self.assertEqual(unpack_report['unpackdirectory'],
                str(fn_expected.parent))
        self.assertEqual(unpack_report['files'], [ str(fn_expected) ])

    def test_file_is_unpacked_by_extension(self):
        fn = pathlib.Path("unpackers") / "gif" / "test.gif"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_for_valid_extension(unpacker)
        self.assertIn('gif', fileresult.labels)

    def test_file_is_unpacked_by_signature(self):
        fn = pathlib.Path("unpackers") / "gif" / "test-prepend-random-data.gif"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_for_valid_extension(unpacker)
        self.assertNotIn('gif', fileresult.labels)
        scanjob.check_for_signatures(unpacker)
        self.assertNotIn('gif', fileresult.labels)
        j = self.scanfile_queue.get()
        self.assertIn('gif', j.fileresult.labels)

    def test_carved_data_is_extracted_from_file(self):
        fn = pathlib.Path("unpackers") / "gif" / "test-prepend-random-data.gif"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_for_valid_extension(unpacker)
        scanjob.check_for_signatures(unpacker)
        j = self.scanfile_queue.get()
        scanjob.carve_file_data(unpacker)
        j = self.scanfile_queue.get()
        synthesized_name = pathlib.Path('.') / \
                ("%s-0x%08x-synthesized-1" % (fn.name,0)) / \
                ("unpacked-0x%x-0x%x" % (0,127))
        self.assertEqual(j.fileresult.filename, synthesized_name)
        self.assertUnpackedPathExists(j.fileresult.filename)

    def test_featureless_file_is_unpacked(self):
        fn = pathlib.Path("unpackers") / "ihex" / "example.txt"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_for_valid_extension(unpacker)
        self.assertEqual(fileresult.labels, set())
        scanjob.check_for_signatures(unpacker)
        self.assertEqual(fileresult.labels, set())
        self.assertEqual(fileresult.unpackedfiles, [])
        scanjob.carve_file_data(unpacker)
        self.assertEqual(fileresult.unpackedfiles, [])
        fileresult.labels.add('text')
        scanjob.check_entire_file(unpacker)
        self.assertEqual(len(fileresult.unpackedfiles), 1)
        j = self.scanfile_queue.get()
        expected_extracted_fn = pathlib.Path('.') / \
                ("%s-0x%08x-ihex-1" % (fn.name, 0)) / "unpacked-from-ihex"
        self.assertEqual(j.fileresult.filename, expected_extracted_fn)
        self.assertUnpackedPathExists(j.fileresult.filename)

    # test to verify how signatures are matched
    # 1. non-overlapping files with unpackers that unpack
    # 2. overlapping files with unpackers that unpack
    # 3. same offset, different unpackers: one unpacks, the other does not
    # 4. same offset, different unpackers that both unpack
    # 5. files with unpackers that do not unpack
    # test carving:

    # 1. file that unpacks by extension but filesize is not the entire file
    #    the remainder of the file is then scanned by signatures
    #    ex: 2 .gbr files concatenated with extension .gbr
    def test_file_with_extension_match_is_carved(self):
        fn = pathlib.Path("unpackers") / "combined" / "double-gimpbrush.gbr"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        self.assertEqual(len(self.result_queue.queue), 3)
        result1 = self.result_queue.get()
        result2 = self.result_queue.get()
        result3 = self.result_queue.get()
        self.assertEqual(result1.filename, fn_abs) # parent file is absolute
        self.assertEqual(result2.filename.name, 'unpacked.gimpbrush') # relative
        self.assertEqual(result2.filename.parent.parent, pathlib.Path('.'))
        self.assertEqual(result3.filename.name, 'unpacked.gimpbrush') # relative
        self.assertEqual(result3.filename.parent.parent, pathlib.Path('.'))

    # 2. ex: 2 .gbr files concatenated with extension .bla
    def test_file_with_signature_match_is_carved(self):
        fn = pathlib.Path("unpackers") / "combined" / "double-gimpbrush.bla"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        self.assertEqual(len(self.result_queue.queue), 3)
        result1 = self.result_queue.get()
        result2 = self.result_queue.get()
        result3 = self.result_queue.get()
        # unpack file at root has absolute path
        self.assertEqual(result1.filename, fn_abs)
        self.assertEqual(result2.filename.name, 'unpacked.gimpbrush')
        self.assertEqual(result2.filename.parent.parent, pathlib.Path('.'))
        self.assertEqual(result3.filename.name, 'unpacked.gimpbrush')
        self.assertEqual(result3.filename.parent.parent, pathlib.Path('.'))

    # 3. ex: kernelconfig (featureless file) concatenated with .gbr
    def test_file_without_features_is_carved(self):
        # TODO: review if this test does what we want it to do
        fn = pathlib.Path("unpackers") / "combined" / "kernelconfig-gif.bla"
        fn_abs = self.testdata_dir / fn
        fileresult = FileResult(fn_abs, None, set(), set())
        fileresult.set_filesize(fn_abs.stat().st_size)

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        except ScanJobError as e:
            if e.e.__class__ != QueueEmptyError:
                raise e
        self.assertEqual(len(self.result_queue.queue), 3)
        result1 = self.result_queue.get()
        result2 = self.result_queue.get()
        result3 = self.result_queue.get()
        # unpack file at root has absolute path
        self.assertEqual(result1.filename, fn_abs)
        self.assertEqual(result2.filename.name, 'unpacked.gif')
        self.assertEqual(result2.filename.parent.parent, pathlib.Path('.'))
        # gif_offset = 202554
        gif_offset = result1.unpackedfiles[0]['offset']
        self.assertEqual(result3.filename.name,
                'unpacked-0x%x-0x%x' % (0,gif_offset-1))

    # 4. Polyglot files


if __name__ == "__main__":
    unittest.main()
