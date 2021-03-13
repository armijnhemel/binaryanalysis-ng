import sys, os
from test.util import *

from UnpackParserException import UnpackParserException
from .UnpackParser import DoomWadUnpackParser

def test_load_standard_wad_file(scan_environment):
    rel_testfile = pathlib.Path('download') / 'game' / 'doom_wad' / 'doom1.wad'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = DoomWadUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() == filesize
    assert r.get_unpacked_files() == []

def test_extracted_wad_file_is_correct(scan_environment):
    padding_length = 5
    orig_testfile = pathlib.Path('download') / 'game' / 'doom_wad' / 'doom1.wad'
    rel_testfile = pathlib.Path('download') / 'game' / 'doom_wad' / 'prepend-doom1.wad'
    abs_orig_testfile = testdir_base / 'testdata' / orig_testfile
    abs_testfile = testdir_base / 'testdata' / rel_testfile
    with open(abs_testfile,"wb") as f:
        f.write(b"A" * padding_length)
        with open(abs_orig_testfile,"rb") as g:
                f.write(g.read())
        	# os.sendfile(f.fileno(), g.fileno(), 0, abs_orig_testfile.stat().st_size)
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = DoomWadUnpackParser(fr, scan_environment, data_unpack_dir, padding_length)
    p.open()
    r = p.parse_and_unpack()
    p.carve()
    p.close()
    assert r.get_length() == filesize - padding_length
    unpacked_file = r.get_unpacked_files()[0].filename
    unpacked_labels = r.get_unpacked_files()[0].labels
    assert pathlib.Path(unpacked_file) == pathlib.Path(data_unpack_dir) / 'unpacked.doomwad'
    assertUnpackedPathExists(scan_environment, unpacked_file)
    assert (scan_environment.unpackdirectory / unpacked_file).stat().st_size == r.get_length()
    # assert set(unpacked_labels) == set(r.get_labels() + ['unpacked'])

def test_load_png_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'png' / 'test.png'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = DoomWadUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException, match = r".*") as cm:
        r = p.parse_and_unpack()
    p.close()


