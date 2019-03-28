import sys
import os
import shutil
import pathlib
import inspect
import unittest

_scriptdir = os.path.dirname(__file__)
sys.path.insert(0,os.path.join(_scriptdir,'..'))

from ScanContext import *
from FileResult import *
from ScanJob import *
from ScanEnvironment import *

import bangfilescans

bangfunctions = inspect.getmembers(bangfilescans, inspect.isfunction)
bangfilefunctions = [func for name, func in bangfunctions
        if func.context == 'file']
bangwholecontextfunctions = [func for name, func in bangfunctions
        if func.context == 'whole']

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
        self.unpackdir = os.path.join(_scriptdir,'unpack')
        self.tmpdir = os.path.join(_scriptdir,'tmp')
        self.resultsdir = os.path.join(_scriptdir,'results')
        self._create_clean_directory(self.unpackdir)
        self._create_clean_directory(self.tmpdir)
        self._create_clean_directory(self.resultsdir)
        self.scancontext = ScanContext(self.unpackdir, self.tmpdir)
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
            paddingname = 'PADDING')

    def _create_clean_directory(self,dirname):
        try:
            shutil.rmtree(dirname)
        except FileNotFoundError:
            pass
        os.mkdir(dirname)
    def _create_padding_file_in_directory(self):
        self.parent_dir = 'a'
        os.makedirs(os.path.join(self.unpackdir, self.parent_dir))
        self.padding_file = os.path.join(self.parent_dir,'PADDING-0x00-0x01')
        f = open(os.path.join(self.unpackdir, self.padding_file), 'wb')
        f.write(b'\0' * 20)
        f.close()
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
        scanjob = ScanJob(self.scancontext, fileresult)
        unpacker = Unpacker()
        scanjob.prepare_for_unpacking()
        scanjob.check_unscannable_file()
        unpacker.append_unpacked_range(0,5) # bytes [0:5) are unpacked
        scanjob.carve_file_data(unpacker, self.scan_environment, self.scanfile_queue)
        j = self.scanfile_queue.get()
        self.assertSetEqual(j.fileresult.labels,set(['padding','synthesized']))

    def test_process_paddingfile_has_correct_labels(self):
        self._create_padding_file_in_directory()
        fileresult = self._create_fileresult_for_file(
                self.padding_file, self.parent_dir, set(['padding']))
        scanjob = ScanJob(self.scancontext, fileresult)
        self.scanfile_queue.put(scanjob)
        try:
            processfile(self.scanfile_queue, self.result_queue,
                    self.process_lock, self.checksum_dict,
                    self.unpackdir,
                    pathlib.Path(self.resultsdir),
                    self.tmpdir, self.dbconn, self.dbcursor,
                    bangfilefunctions, self.scan_environment
                    )
        except QueueEmptyError:
            pass
        result = self.result_queue.get()
        self.assertSetEqual(result.labels,set(['binary','padding']))


if __name__=="__main__":
    unittest.main()

