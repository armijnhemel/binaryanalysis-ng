import sys, os
from util import *
from mock_metadirectory import *

from bang.parsers.archivers.mozilla_mar.UnpackParser import MozillaMar

def test_load_mozilla_mar_file(scan_environment):
    testfile = testdir_base / 'testdata' / 'download' / 'archivers' / 'mozilla_mar' / 'test-xz.mar'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open() as opened_md:
        p = MozillaMar(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        unpacked_fn = unpacked_md.unpacked_path(pathlib.Path('Contents') / 'MacOS' / 'defaults' / 'pref' / 'channel-prefs.js')
        assert unpacked_fn in unpacked_md.unpacked_files
        unpacked_fn_abs = scan_environment.unpackdirectory / unpacked_fn
        with open(unpacked_fn_abs, 'rb') as f:
            assert f.read(2) == b'\xfd\x37'

