import sys, os
from util import *
from mock_metadirectory import *

from bang.parsers.archivers.mozilla_mar.UnpackParser import MozillaMar

def test_load_mozilla_mar_file(scan_environment):
    rel_testfile = pathlib.Path('download') / 'archivers' / 'mozilla_mar' / 'test-xz.mar'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
    p = MozillaMar(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() <= filesize
    extracted_fn = data_unpack_dir / 'Contents' / 'MacOS' / 'defaults' / 'pref' / 'channel-prefs.js'
    assert r.get_unpacked_files()[0].filename == extracted_fn
    assert r.get_unpacked_files()[0].labels == set()
    assertUnpackedPathExists(scan_environment, extracted_fn)
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    with open(extracted_fn_abs,"rb") as f:
        assert f.read(2) == b'\xfd\x37'
