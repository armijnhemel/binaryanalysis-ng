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
        self.parent_dir = 'a'
        self._make_directory_in_unpackdir(self.parent_dir)
        self.padding_file = os.path.join(self.parent_dir,'PADDING-0x00-0x01')
        f = open(os.path.join(self.unpackdir, self.padding_file), 'wb')
        f.write(b'\0' * 20)
        f.close()

    def _copy_file_from_testdata(self, path):
        unpacked_path = os.path.join(self.unpackdir, path)
        unpacked_dir = os.path.dirname(unpacked_path)
        try:
            os.makedirs(unpacked_dir)
        except FileExistsError:
            pass
        shutil.copy(os.path.join(self.testdata_dir, path), unpacked_path)

    def _create_css_file_in_directory(self):
        self.parent_dir = 'a'
        self._make_directory_in_unpackdir(self.parent_dir)
        self.css_file = os.path.join(self.parent_dir,'cascade.css')
        unpackedpath = os.path.join(self.unpackdir, self.css_file)
        shutil.copy(os.path.join(self.testdata_dir, self.css_file),
                unpackedpath)

    def _create_absolute_path_object(self,fn):
        return pathlib.Path(os.path.join(self.unpackdir, fn))

    def _create_fileresult_for_file(self,child,parent,labels):
        return FileResult(
                self._create_absolute_path_object(child), child,
                self._create_absolute_path_object(parent), parent, labels )

    def test_carved_padding_file_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = self._create_fileresult_for_file(
                self.padding_file, self.parent_dir, [])
        scanjob = ScanJob(fileresult)
        scanjob.set_scanenvironment(self.scan_environment)
        unpacker = Unpacker()
        scanjob.prepare_for_unpacking()
        scanjob.check_unscannable_file()
        unpacker.append_unpacked_range(0,5) # bytes [0:5) are unpacked
        scanjob.carve_file_data(unpacker)
        j = self.scanfile_queue.get()
        self.assertSetEqual(j.fileresult.labels,set(['padding','synthesized']))

    def test_process_paddingfile_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = self._create_fileresult_for_file(
                self.padding_file, self.parent_dir, set(['padding']))
        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        result = self.result_queue.get()
        self.assertSetEqual(result.labels,set(['binary','padding']))

    def test_process_css_file_has_correct_labels(self):
        # /home/tim/bang-test-scrap/bang-scan-jucli3nm/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/www/luci-static/bootstrap/cascade.css
        self._create_css_file_in_directory()
        fileresult = self._create_fileresult_for_file(
                self.css_file, self.parent_dir, set())
        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        result = self.result_queue.get()
        self.assertSetEqual(result.labels,set(['text','css']))

    def test_openwrt_version_has_correct_labels(self):
        # openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/etc/openwrt_version
        fn = "a/openwrt_version"
        self._copy_file_from_testdata(fn)
        fileresult = self._create_fileresult_for_file(fn,
                os.path.dirname(fn), set())

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        result = self.result_queue.get()
        self.assertSetEqual(result.labels,set(['text','base64','urlsafe']))

    def test_dhcpv6sh_has_correct_labels(self):
        # /home/tim/bang-test-scrap/bang-scan-wd8il1i5/unpack/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img.gz-gzip-1/openwrt-18.06.1-brcm2708-bcm2710-rpi-3-ext4-sysupgrade.img-ext2-1/lib/netifd/proto/dhcpv6.sh
        fn = "a/dhcpv6.sh"
        self._copy_file_from_testdata(fn)
        fileresult = self._create_fileresult_for_file(fn,
                os.path.dirname(fn), set())

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        result = self.result_queue.get()
        self.assertSetEqual(result.labels,set(['text','script','shell']))

    def test_gzip_unpacks_to_right_directory(self):
        fn = "a/hello.gz"
        self._copy_file_from_testdata(fn)
        fileresult = self._create_fileresult_for_file(fn,
                os.path.dirname(fn), set())

        scanjob = ScanJob(fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.dbconn, self.dbcursor, self.scan_environment)
        except QueueEmptyError:
            pass
        result1 = self.result_queue.get()
        result2 = self.result_queue.get()
        self.assertEqual(result2.filename,'a/hello.gz-gzip-1/hello')



if __name__=="__main__":
    unittest.main()

