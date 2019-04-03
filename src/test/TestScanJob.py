import sys
import os
import shutil
import pathlib
import inspect
import unittest

from TestUtil import *

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

    def _create_absolute_path_object(self,fn):
        return pathlib.Path(os.path.join(self.unpackdir, fn))

    def test_carved_padding_file_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = create_fileresult_for_path(self.unpackdir, self.padding_file)
        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        scanjob.initialize()
        unpacker = Unpacker(self.unpackdir)
        scanjob.prepare_for_unpacking()
        scanjob.check_unscannable_file()
        unpacker.append_unpacked_range(0,5) # bytes [0:5) are unpacked
        scanjob.carve_file_data(unpacker)
        j = self.scanfile_queue.get()
        self.assertSetEqual(j.fileresult.labels,set(['padding','synthesized']))

    def test_process_paddingfile_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = create_fileresult_for_path(self.unpackdir, self.padding_file, set(['padding']))
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
        self.assertSetEqual(result.labels,set(['binary','padding']))

    def test_process_css_file_has_correct_labels(self):
        # /home/tim/bang-test-scrap/bang-scan-jucli3nm/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/www/luci-static/bootstrap/cascade.css
        fn = pathlib.Path("a/cascade.css")
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir,fn,set())
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
        self.assertSetEqual(result.labels,set(['text','css']))

    def test_openwrt_version_has_correct_labels(self):
        # openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/etc/openwrt_version
        fn = pathlib.Path("a/openwrt_version")
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir,fn,set())
        # fileresult = self._create_fileresult_for_file(fn, os.path.dirname(fn), set())

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
        self.assertSetEqual(result.labels,set(['text','base64','urlsafe']))

    def test_dhcpv6sh_has_correct_labels(self):
        # /home/tim/bang-test-scrap/bang-scan-wd8il1i5/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/lib/netifd/proto/dhcpv6.sh
        fn = pathlib.Path("a/dhcpv6.sh")
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn)

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
        self.assertSetEqual(result.labels,set(['text','script','shell']))

    def test_gzip_unpacks_to_right_directory(self):
        fn = pathlib.Path("a/hello.gz")
        self._copy_file_from_testdata(fn)
        fileresult = create_fileresult_for_path(self.unpackdir, fn, set())

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
        self.assertEqual(str(result2.filename), str(fn)+'-gzip-1/hello')



if __name__=="__main__":
    unittest.main()

