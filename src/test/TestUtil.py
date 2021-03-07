import os
import sys
import shutil
import pathlib
import unittest

_scriptdir = os.path.dirname(__file__)

from bangsignatures import maxsignaturesoffset
# import bangfilescans

from FileResult import *
from ScanEnvironment import *
from .mock_queue import *
from .mock_db import *


def create_fileresult_for_path(unpackdir, path, labels, calculate_size=True):
    parentlabels = set()
    fr = FileResult(path, str(path.parent), parentlabels, labels)
    if calculate_size:
        fp = pathlib.Path(unpackdir) / path
        fr.set_filesize(fp.stat().st_size)
    return fr

class TestBase(unittest.TestCase):
    # create a temporary directory and copy
    # the test file to the temporary directory
    def setUp(self):
        self.testdata_dir = pathlib.Path(_scriptdir).resolve() / 'testdata'
        self.unpackdir = pathlib.Path(_scriptdir).resolve() / 'unpack'
        self.tmpdir = pathlib.Path(_scriptdir).resolve() / 'tmp'
        self.resultsdir = pathlib.Path(_scriptdir).resolve() / 'results'
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
            createjson = True,
            runfilescans = True, # TODO: is this the correct value?
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

    def _create_clean_directory(self, dirname):
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

    def assertUnpackedPathExists(self, extracted_fn, message=None):
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertTrue(extracted_fn_abs.exists(), message)

    def assertUnpackedPathDoesNotExist(self, extracted_fn, message=None):
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertFalse(extracted_fn_abs.exists(), message)

