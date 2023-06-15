import os
import sys
import pathlib
import pytest
import shutil
import threading

from bang.meta_directory import *
# from FileResult import *
from bang.scan_environment import *
from bang.signatures import maxsignaturesoffset
from bang import signatures

from mock_queue import *

from bang.UnpackParser import UnpackParser
from bang.UnpackParserException import UnpackParserException
from UnpackResults import UnpackResults

_scriptdir = os.path.dirname(__file__)
testdir_base = pathlib.Path(_scriptdir).resolve()

def create_meta_directory_for_path(scan_environment, path, is_root):
    path_md = MetaDirectory(scan_environment.unpackdirectory, None, is_root)
    path_md.file_path = scan_environment.temporarydirectory / path
    return path_md

def reopen_md(orig_md):
    return MetaDirectory.from_md_path(orig_md.meta_root, orig_md.md_path)

def create_test_file(scan_environment, path, content):
    abs_path = scan_environment.temporarydirectory / path
    with abs_path.open('wb') as f:
        f.write(content)
    return abs_path

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
    _create_clean_directory(tmp_dir / 'unpack')
    _create_clean_directory(tmp_dir / 'tmp')
    se = ScanEnvironment(
        unpackdirectory = tmp_dir / 'unpack',
        temporarydirectory = tmp_dir / 'tmp',
        scan_queue = MockQueue(),
    )
    se.parsers.unpackparsers = signatures.get_unpackers()
    se.scan_semaphore = threading.Semaphore(1)
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

def parse_success(self):
    self.unpacked_size = self.length

def parse_fail(self):
    raise UnpackParserException("failing unpackparser")

def create_unpackparser(name, fail = False,
        extensions = [], signatures = [], length = 0,
        pretty_name = None, scan_if_featureless = False): 
    if fail:
        parse_method = parse_fail
    else:
        parse_method = parse_success
    if not pretty_name:
        pretty_name = name
    c = type(name, (UnpackParser,), {
                'extensions': extensions,
                'signatures': signatures,
                'scan_if_featureless': scan_if_featureless,
                'parse_from_offset': parse_method,
                'pretty_name': pretty_name,
                'length': length,
                'labels': [],
                'metadata': {},
            })
    return c


class UnpackParserZeroLength(UnpackParser):

    pretty_name = "zero_length"
    extensions = []
    signatures = [(1,b'BB')]

    def parse(self):
        self.unpacked_size = 0
        return
    def calculate_unpacked_size(self):
        return 0


