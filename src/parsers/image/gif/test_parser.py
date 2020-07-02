import sys, os
from test.util import *

from UnpackParserException import UnpackParserException
from .UnpackParser import GifUnpackParser

def test_load_standard_gif_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test.gif'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GifUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() == filesize
    assert r.get_unpacked_files() == []
    assert r.get_metadata()['width'] == 3024

def test_extracted_gif_file_is_correct(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'gif' / 'test-prepend-random-data.gif'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GifUnpackParser(fr, scan_environment, data_unpack_dir, 128)
    p.open()
    r = p.parse_and_unpack()
    p.carve()
    p.close()
    assert r.get_length() == 7073713
    unpacked_file = r.get_unpacked_files()[0].filename
    unpacked_labels = r.get_unpacked_files()[0].labels
    assert pathlib.Path(unpacked_file) == pathlib.Path(data_unpack_dir) / 'unpacked.gif'
    assertUnpackedPathExists(scan_environment, unpacked_file)
    assert (scan_environment.unpackdirectory / unpacked_file).stat().st_size == r.get_length()
    assert r.get_metadata()['width'] == 3024
    assert set(unpacked_labels) == set(r.get_labels() + ['unpacked'])

def test_load_png_file(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'png' / 'test.png'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    data_unpack_dir = rel_testfile.parent / 'some_dir'
    p = GifUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    with pytest.raises(UnpackParserException, match = r".*") as cm:
        r = p.parse_and_unpack()
    p.close()


