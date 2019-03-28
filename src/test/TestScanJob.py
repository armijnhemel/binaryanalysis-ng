import sys
import os
import shutil
import pathlib
import inspect
import unittest

_scriptdir = os.path.dirname(__file__)
sys.path.insert(0,os.path.join(_scriptdir,'..'))

from FileResult import *
from ScanJob import *
from ScanEnvironment import *

import bangfilescans

class QueueEmptyError(Exception):
    pass

class MockQueue:
    def __init__(self):
        self.queue = []
    def get(self, timeout=0):
        try:
            return self.queue.pop()
        except IndexError:
            raise QueueEmptyError()
    def put(self, job):
        self.queue.append(job)
    def task_done(self):
        pass

class MockLock:
    def acquire(self): pass
    def release(self): pass

class MockDBConn:
    pass

class MockDBCursor:
    pass

class TestScanJob(unittest.TestCase):

    def setUp(self):
        self.testdata_dir = os.path.join(_scriptdir,'testdata')
        self.unpackdir = os.path.join(_scriptdir,'unpack')
        self.tmpdir = os.path.join(_scriptdir,'tmp')
        self.resultsdir = os.path.join(_scriptdir,'results')
        self._create_clean_directory(self.unpackdir)
        self._create_clean_directory(self.tmpdir)
        self._create_clean_directory(self.resultsdir)
        self.scanfile_queue = MockQueue()
        self.result_queue = MockQueue()
        self.process_lock = MockLock()
        self.checksum_dict = {}
        self.dbconn = MockDBConn()
        self.dbcursor = MockDBCursor()
        self.scan_environment = ScanEnvironment(
            maxbytes = max(200000, maxsignaturesoffset+1),
            readsize = 10240,
            createbytecounter = False,
            tlshmaximum = sys.maxsize,
            synthesizedminimum = 10,
            logging = False,
            paddingname = 'PADDING',
            unpackdirectory = self.unpackdir,
            temporarydirectory = self.tmpdir,
            resultsdirectory = self.resultsdir,
            scanfilequeue = self.scanfile_queue,
            resultqueue = self.result_queue,
            processlock = self.process_lock,
            checksumdict = self.checksum_dict,
            )

    def _create_clean_directory(self,dirname):
        try:
            shutil.rmtree(dirname)
        except FileNotFoundError:
            pass
        os.mkdir(dirname)

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
            processfile(pathlib.Path(self.resultsdir),
                    self.dbconn, self.dbcursor,
                    self.scan_environment
                    )
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
            processfile(pathlib.Path(self.resultsdir),
                    self.dbconn, self.dbcursor,
                    self.scan_environment
                    )
        except QueueEmptyError:
            pass
        result = self.result_queue.get()
        self.assertSetEqual(result.labels,set(['text','css']))



if __name__=="__main__":
    unittest.main()

