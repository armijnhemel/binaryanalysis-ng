import os
import sys
import pathlib
import pytest
import shutil

from FileResult import *
from ScanEnvironment import *
from bangsignatures import maxsignaturesoffset
from .mock_queue import *
from .mock_db import *

_scriptdir = os.path.dirname(__file__)
testdir_base = pathlib.Path(_scriptdir).resolve()


@pytest.fixture(scope='module')
def scan_environment(tmp_path_factory):
    tmp_dir = tmp_path_factory.mktemp("bang")
    return ScanEnvironment(
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

def fileresult(basedir, rel_path, labels, calculate_size = True):
    parentlabels = set()
    fr = FileResult(rel_path, str(rel_path.parent), parentlabels, labels)
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

def assertUnpackedPathExists(scan_environment, extracted_fn, message=None):
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    assert extracted_fn_abs.exists(), message

def assertUnpackedPathDoesNotExist(scan_environment, extracted_fn, message=None):
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    assert extracted_fn_abs.exists(), message

