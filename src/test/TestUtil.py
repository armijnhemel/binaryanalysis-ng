import os
import sys
import shutil
import pathlib
import unittest
import collections

_scriptdir = os.path.dirname(__file__)
sys.path.insert(0,os.path.join(_scriptdir,'..'))

from bangsignatures import maxsignaturesoffset
import bangfilescans

from FileResult import *
from ScanEnvironment import *

def create_fileresult_for_path(unpackdir, path, labels=set([]),
        calculate_size=True):
    fp = pathlib.Path(unpackdir) / path
    fr = FileResult(path, str(path.parent), labels)
    if calculate_size:
        fr.set_filesize(fp.stat().st_size)
    return fr

class QueueEmptyError(Exception):
    pass

class MockQueue:
    def __init__(self):
        self.queue = collections.deque() #[]
    def get(self, timeout=0):
        try:
            return self.queue.popleft()
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


class TestBase(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.testdata_dir = pathlib.Path(_scriptdir) / 'testdata'
        self.unpackdir = pathlib.Path(_scriptdir) / 'unpack'
        self.tmpdir = pathlib.Path(_scriptdir) / 'tmp'
        self.resultsdir = pathlib.Path(_scriptdir) / 'results'
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
            resultsdirectory = pathlib.Path(self.resultsdir),
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

    # remove the temporary directory
    def tearDown(self):
        shutil.rmtree(self.unpackdir)
        shutil.rmtree(self.tmpdir)
        shutil.rmtree(self.resultsdir)

    def _copy_file_from_testdata(self, path, name=None):
        if name is None:
            name = path
        unpacked_path = self.unpackdir / name
        unpacked_dir = unpacked_path.parent
        try:
            os.makedirs(unpacked_dir)
        except FileExistsError:
            pass
        shutil.copy(self.testdata_dir / path, unpacked_path)


