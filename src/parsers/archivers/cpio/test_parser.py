import sys, os
from test.util import *

from .UnpackParser import CpioNewAsciiUnpackParser, \
    CpioNewCrcUnpackParser, CpioPortableAsciiUnpackParser, \
    rewrite_symlink

def test_load_cpio_file_new_ascii(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-new.cpio'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
    p = CpioNewAsciiUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() <= filesize
    extracted_fn = data_unpack_dir / 'test.sgi'
    assert r.get_unpacked_files()[0].filename == extracted_fn
    assert r.get_unpacked_files()[0].labels == set()
    assertUnpackedPathExists(scan_environment, extracted_fn)
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    with open(extracted_fn_abs,"rb") as f:
        assert f.read(2) == b'\x01\xda'

def test_load_cpio_file_new_ascii_with_offset(scan_environment):
    padding_length = 5
    rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-new-padded.cpio'
    orig_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-new.cpio'
    abs_orig_testfile = testdir_base / 'testdata' / orig_testfile
    abs_testfile = testdir_base / 'testdata' / rel_testfile
    with open(abs_testfile,"wb") as f:
        f.write(b"A" * padding_length)
        with open(abs_orig_testfile,"rb") as g:
                f.write(g.read())
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name + "-1")
    p = CpioNewAsciiUnpackParser(fr, scan_environment, data_unpack_dir, padding_length)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() <= filesize
    extracted_fn = data_unpack_dir / 'test.sgi'
    assert r.get_unpacked_files()[0].filename == extracted_fn
    assert r.get_unpacked_files()[0].labels == set()
    assertUnpackedPathExists(scan_environment, extracted_fn)
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    with open(extracted_fn_abs,"rb") as f:
        assert f.read(2) == b'\x01\xda'



def test_load_cpio_file_portable_ascii(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-old.cpio'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name+"-2")
    p = CpioPortableAsciiUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() <= filesize
    extracted_fn = data_unpack_dir / 'test.sgi'
    assert r.get_unpacked_files()[0].filename == extracted_fn
    assert r.get_unpacked_files()[0].labels == set()
    assertUnpackedPathExists(scan_environment, extracted_fn)

def test_unpack_different_filetypes(scan_environment):
    rel_testfile = pathlib.Path('download') / 'archivers' / 'cpio' / 'initramfs.cpio'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name+"-3")
    p = CpioNewAsciiUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() <= filesize

    # check if etc is a directory
    extracted_fn = data_unpack_dir / 'etc'
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    assert extracted_fn_abs.is_dir()
    extracted_labels = [ i for i in r.get_unpacked_files() if i.filename == extracted_fn][0].labels
    assert extracted_labels == set()

    # check if /linuxrc is a symlink to bin/busybox
    # extracted_fn = data_unpack_dir / 'bin' / 'dbclient'
    extracted_fn = data_unpack_dir / 'linuxrc'
    extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
    assert extracted_fn_abs.is_symlink()
    assert extracted_fn_abs.resolve().name == 'busybox'
    assert extracted_fn_abs.resolve().parent.name == 'bin'
    extracted_labels = [ i for i in r.get_unpacked_files() if i.filename == extracted_fn][0].labels
    assert 'symbolic link' in extracted_labels

    # check if device /dev/zero is skipped
    extracted_fn = data_unpack_dir / 'dev' / 'zero'
    assertUnpackedPathDoesNotExist(scan_environment, extracted_fn)
    extracted_files = [ i for i in r.get_unpacked_files() if i.filename == extracted_fn]
    assert extracted_files == []


def test_cpio_with_absolute_path(scan_environment):
    rel_testfile = pathlib.Path('unpackers') / 'cpio' / 'test-absolute-path.cpio'
    copy_testfile_to_environment(testdir_base / 'testdata', rel_testfile, scan_environment)
    fr = fileresult(testdir_base / 'testdata', rel_testfile, set())
    filesize = fr.filesize
    data_unpack_dir = rel_testfile.parent / ('unpack-'+rel_testfile.name+"-4")
    p = CpioNewAsciiUnpackParser(fr, scan_environment, data_unpack_dir, 0)
    p.open()
    r = p.parse_and_unpack()
    p.close()
    assert r.get_length() <= filesize

    extracted_fn = data_unpack_dir / 'e' / 't.sgi'
    assertUnpackedPathExists(scan_environment, extracted_fn)
    extracted_labels = [ i for i in r.get_unpacked_files() if i.filename == extracted_fn][0].labels
    assert extracted_labels == set()


# TODO: is this test relevant if we change the unpacking strategy?
def test_rewrite_symlink():
    p = CpioNewAsciiUnpackParser(None, None, None, 0)

    expected_results = [
        ('test/dir/a.txt', '../c.txt', '../c.txt'),
        ('test/dir/a.txt', '../../c.txt', '../../c.txt'),
        ('test/dir/a.txt', '../../../../../../../../../c.txt', '../../c.txt'),
        ('/test/dir/a.txt', '../../../../../../../../../c.txt', '../../c.txt'),
        ('test/dir/a.txt', '/a/b/c.txt', '../../a/b/c.txt'),
        ('test/dir/a.txt', '/a/../b/c.txt', '../../b/c.txt'),
        ('test/dir/a.txt', '/a/../../../b/c.txt', '../../b/c.txt'),
        ('/some/test/dir/a.txt', '/a/b/c.txt', '../../../a/b/c.txt'),
    ]
    for filename, target, expected_link in expected_results:
        ptarget = pathlib.Path(target)
        pfile = pathlib.Path(filename)
        plink = pathlib.Path(expected_link)
        assert rewrite_symlink(pfile, ptarget) == plink

# Following archive formats are supported: binary, old ASCII, new ASCII, crc, HPUX binary, HPUX old ASCII, old tar, and POSIX.1 tar.

