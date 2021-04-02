import os
import sys
import pathlib
import pytest
import shutil

from FileResult import *
from ScanEnvironment import *
from bangsignatures import maxsignaturesoffset
import bangsignatures

from .mock_queue import *
from .mock_db import *

from UnpackParser import UnpackParser
from UnpackParserException import UnpackParserException
from UnpackResults import UnpackResults

_scriptdir = os.path.dirname(__file__)
testdir_base = pathlib.Path(_scriptdir).resolve()

def _create_clean_directory(dirpath):
    try:
        shutil.rmtree(dirpath)
    except FileNotFoundError:
        pass
    dirpath.mkdir()

# TODO: function scope
@pytest.fixture(scope='function')
def scan_environment(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("bang")
    print("DEBUG: tmp_dir=", tmp_dir)
    _create_clean_directory(tmp_dir / 'unpack')
    _create_clean_directory(tmp_dir / 'tmp')
    _create_clean_directory(tmp_dir / 'results')
    se = ScanEnvironment(
        maxbytes = max(200000, maxsignaturesoffset+1),
        readsize = 10240,
        createbytecounter = False,
        createjson = True,
        runfilescans = True, # TODO: is this the correct value?
        tlshmaximum = sys.maxsize,
        synthesizedminimum = 10,
        logging = False,
        paddingname = 'PADDING',
        unpackdirectory = tmp_dir / 'unpack',
        temporarydirectory = tmp_dir / 'tmp',
        resultsdirectory = tmp_dir / 'results',
        scanfilequeue = MockQueue(),
        resultqueue = MockQueue(),
        processlock = MockLock(),
        checksumdict = {},
    )
    se.set_unpackparsers(bangsignatures.get_unpackers())
    return se

def fileresult(basedir, rel_path, labels, calculate_size = True):
    parentlabels = set()
    parent = FileResult(None, rel_path.parent, parentlabels)
    fr = FileResult(parent, rel_path, labels)
    if calculate_size:
        fp = pathlib.Path(basedir) / rel_path
        fr.set_filesize(fp.stat().st_size)
    return fr

def copy_testfile_to_environment(basedir, rel_path, scan_environment):
    unpacked_path = scan_environment.unpackdirectory / rel_path
    try:
        os.makedirs(unpacked_path.parent)
    except FileExistsError:
        pass
    shutil.copy(basedir / rel_path, unpacked_path)

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


def create_unpackparser_for_path(scan_environment, testdata_dir, rel_testfile, unpackparser, offset,
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
        fileresult = FileResult(None, testdata_dir / rel_testfile, set())
    if calculate_size:
        path = scan_environment.get_unpack_path_for_fileresult(fileresult)
        fileresult.set_filesize(path.stat().st_size)
    p = unpackparser(fileresult, scan_environment, data_unpack_dir, offset)
    return p


class UnpackParserExtractEx1(UnpackParser):
    pretty_name = "ex1_extract"
    extensions = ['.ex1']
    def calculate_unpacked_size(self):
        self.unpacked_size = self.fileresult.filesize
    def parse(self):
        pass
    def _write_unpacked_file(self, fn):
        outfile_full = self.scan_environment.unpack_path(self.rel_unpack_dir / pathlib.Path(fn))
        with open(outfile_full,"wb") as f:
            f.write(b"A"*40)
    def unpack(self):
        fns = ["ex1_first", "ex1_second" ]
        for fn in fns:
            self._write_unpacked_file(fn)
        return [ FileResult(self.fileresult, self.rel_unpack_dir / pathlib.Path(fn), []) for fn in fns ]

class UnpackParserExtractEx1Carve(UnpackParserExtractEx1):
    extensions = ['.ex1']
    pretty_name = "ex1_extract_carve"
    def calculate_unpacked_size(self):
        self.unpacked_size = max(self.fileresult.filesize - 5, 0)

class UnpackParserExtractEx1Fail(UnpackParser):
    pretty_name = "ex1_extract_fail"
    extensions = ['.ex1']
    pass

class UnpackParserExtractSig1(UnpackParser):
    pretty_name = "sig1_extract"
    extensions = []
    signatures = [(2,b'AA')]
    
    def calculate_unpacked_size(self):
        self.unpacked_size = self.fileresult.filesize
    def parse(self):
        pass
    def _write_unpacked_file(self, fn):
        outfile_full = self.scan_environment.unpack_path(self.rel_unpack_dir / pathlib.Path(fn))
        with open(outfile_full,"wb") as f:
            f.write(b"A"*40)
    def unpack(self):
        fns = ["sig1_first", "sig1_second" ]
        for fn in fns:
            self._write_unpacked_file(fn)
        return [ FileResult(self.fileresult, self.rel_unpack_dir / pathlib.Path(fn), []) for fn in fns ]

class UnpackParserExtractSig1Fail(UnpackParser):
    pretty_name = "sig1_extract_fail"
    extensions = []
    signatures = [(2,b'AA')]

class UnpackParserZeroLength(UnpackParser):

    pretty_name = "zero_length"
    extensions = []
    signatures = [(1,b'BB')]

    def parse(self):
        return
    def calculate_unpacked_size(self):
        return 0



def assertUnpackedPathExists(scan_environment, extracted_fn, message=None):
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    assert extracted_fn_abs.exists(), message

def assertUnpackedPathDoesNotExist(scan_environment, extracted_fn, message=None):
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    assert not extracted_fn_abs.exists(), message

