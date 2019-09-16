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
        f = open(os.path.join(self.unpackdir, self.padding_file), 'wb')
        f.write(b'\0' * 20)
        f.close()

    def _create_absolute_path_object(self, fn):
        return pathlib.Path(os.path.join(self.unpackdir, fn))

    def test_carved_padding_file_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = create_fileresult_for_path(self.unpackdir,
                self.padding_file, set(), calculate_size=True)
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
        fileresult = create_fileresult_for_path(self.unpackdir,
                self.padding_file, set(['padding']), calculate_size=True)
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
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)
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
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)
        # fileresult = self._create_fileresult_for_file(fn, os.path.dirname(fn), set())

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
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self._copy_file_from_testdata(rel_testfile)
        fileresult = create_fileresult_for_path(self.unpackdir, rel_testfile,
                set(), calculate_size=True)

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

        self.assertEqual(result.filename, rel_testfile)
        self.assertSetEqual(result.labels, set(['text', 'kernel configuration']))

    def test_gzip_unpacks_to_right_directory(self):
        fn = pathlib.Path("a/hello.gz")
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self.assertEqual(str(result2.filename), str(fn)+'-0x00000000-gzip-1/hello')

    def test_report_has_correct_path(self):
        fn = pathlib.Path("a/hello.gz")
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self.assertEqual(unpack_report['unpackdirectory'],
                str(fn)+'-0x00000000-gzip-1')
        self.assertEqual(unpack_report['files'],
                [ str(fn)+'-0x00000000-gzip-1/hello' ])

    def test_file_is_unpacked_by_extension(self):
        fn = pathlib.Path("unpackers") / "gif" / "test.gif"
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_for_valid_extension(unpacker)
        # j = self.scanfile_queue.get()
        self.assertIn('gif', fileresult.labels)

    def test_file_is_unpacked_by_signature(self):
        fn = pathlib.Path("unpackers") / "gif" / "test-prepend-random-data.gif"
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        synthesized_name = fn.parent / \
                ("%s-0x%08x-synthesized-1" % (fn.name,0)) / \
                ("unpacked-0x%x-0x%x" % (0,127))
        self.assertEqual(j.fileresult.filename, synthesized_name)
        self.assertUnpackedPathExists(j.fileresult.filename)

    def test_featureless_file_is_unpacked(self):
        fn = pathlib.Path("unpackers") / "ihex" / "example.txt"
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        expected_extracted_fn = fn.parent / \
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
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self.assertEqual(result1.filename, fn)
        self.assertEqual(result2.filename.name, 'unpacked.gimpbrush')
        self.assertEqual(result3.filename.name, 'unpacked.gimpbrush')

    # 2. ex: 2 .gbr files concatenated with extension .bla
    def test_file_with_signature_match_is_carved(self):
        fn = pathlib.Path("unpackers") / "combined" / "double-gimpbrush.bla"
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self.assertEqual(result1.filename, fn)
        self.assertEqual(result2.filename.name, 'unpacked.gimpbrush')
        self.assertEqual(result3.filename.name, 'unpacked.gimpbrush')

    # 3. ex: kernelconfig (featureless file) concatenated with .gbr
    def test_file_without_features_is_carved(self):
        # TODO: review if this test does what we want it to do
        fn = pathlib.Path("unpackers") / "combined" / "kernelconfig-gif.bla"
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set(),
                calculate_size=True)

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
        self.assertEqual(result1.filename, fn)
        self.assertEqual(result2.filename.name, 'unpacked.gif')
        # gif_offset = 202554
        gif_offset = result1.unpackedfiles[0]['offset']
        self.assertEqual(result3.filename.name,
                'unpacked-0x%x-0x%x' % (0,gif_offset-1))

    # 4. Polyglot files


if __name__ == "__main__":
    unittest.main()
