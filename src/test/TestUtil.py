import os
import sys
import shutil
import pathlib
import unittest
import collections

_scriptdir = os.path.dirname(__file__)

from bangsignatures import maxsignaturesoffset
import bangsignatures
import bangfilescans

from FileResult import *
from ScanEnvironment import *
from UnpackParser import UnpackParser
from UnpackResults import UnpackResults

def create_fileresult_for_path(unpackdir, path, labels, calculate_size=False):
    parentlabels = set()
    parent = FileResult(None, path.parent, parentlabels)
    fr = FileResult(parent, path, labels)
    if calculate_size:
        fp = pathlib.Path(unpackdir) / path
        fr.set_filesize(fp.stat().st_size)
    return fr

def parse_and_unpack_success(self):
    r = UnpackResults()
    fr = FileResult(self.fileresult, self.get_carved_filename(), set())
    r.set_unpacked_files([fr])
    r.set_length(self.length)
    return r
    
def parse_and_unpack_fail(self):
    raise UnpackParserException("failing unpackparser")

def create_unpackparser(name, fail = False,
        extensions = [], signatures = [], length = 0,
        pretty_name = '', scan_if_featureless = False): 
    if fail:
        parse_and_unpack_method = parse_and_unpack_fail
    else:
        parse_and_unpack_method = parse_and_unpack_success
    c = type(name, (UnpackParser,), {
                'extensions': extensions,
                'signatures': signatures,
                'scan_if_featureless': scan_if_featureless,
                'parse_and_unpack': parse_and_unpack_method,
                'pretty_name': pretty_name,
                'length': length
            })
    return c



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
    def commit(self):
        pass

class MockDBCursor:
    def execute(self, query, args):
        pass
    def fetchall(self):
        return []


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
            createjson = False,
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
        self.scan_environment.set_unpackparsers(bangsignatures.get_unpackers())

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

    def get_testfile_size(self, rel_testfile):
        abs_testfile = self.testdata_dir / rel_testfile
        return abs_testfile.stat().st_size

    def create_unpackparser_for_path(self, rel_testfile, unpackparser, offset,
            data_unpack_dir = pathlib.Path('.'), has_unpack_parent = False,
            calculate_size = True):
        """Creates an unpackparser of type unpackparser to unpack the file
        rel_testfile, starting at offset.
        data_unpack_dir is the path of the directory to which any files are
            extracted. The path is relative to the unpack root directory.
        has_unpack_parent indicates if this file is unpacked from another file.
            if True, rel_testfile is relative to the unpack root directory,
            if False, rel_testfile is relative to the testdata directory.
        calculate_size will calculate the size of the file. If the file does not
            exist for some reason, this flag can be set to False. Default is
            True.
        """
        # self._copy_file_from_testdata(rel_testfile)
        if has_unpack_parent:
            parent = FileResult(None, rel_testfile.parent, set())
            fileresult = FileResult(parent, rel_testfile, set())
        else:
            fileresult = FileResult(None, self.testdata_dir / rel_testfile, set())
        if calculate_size:
            path = self.scan_environment.get_unpack_path_for_fileresult(fileresult)
            fileresult.set_filesize(path.stat().st_size)
        p = unpackparser(fileresult, self.scan_environment, data_unpack_dir,
                offset)
        return p

    def assertUnpackedPathExists(self, extracted_fn, message=None):
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertTrue(extracted_fn_abs.exists(), message)

    def assertUnpackedPathDoesNotExist(self, extracted_fn, message=None):
        extracted_fn_abs = pathlib.Path(self.unpackdir) / extracted_fn
        self.assertFalse(extracted_fn_abs.exists(), message)

