import sys, os
from util import *
from mock_metadirectory import *
from bang.log import log

from bang.parsers.archivers.cpio.UnpackParser import CpioNewAsciiUnpackParser, \
    CpioNewCrcUnpackParser, CpioPortableAsciiUnpackParser

def test_load_cpio_file_new_ascii(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-new.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open('rb') as opened_md:
        p = CpioNewAsciiUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        extracted_fn = unpacked_md.unpacked_path(pathlib.Path('test.sgi'))
        assert extracted_fn in unpacked_md.unpacked_files
        extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
        assert extracted_fn_abs.exists()
        with open(extracted_fn_abs,"rb") as f:
            assert f.read(2) == b'\x01\xda'


def test_load_cpio_file_portable_ascii(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-old.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open('rb') as opened_md:
        p = CpioPortableAsciiUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        extracted_fn = unpacked_md.unpacked_path(pathlib.Path('test.sgi'))
        assert extracted_fn in unpacked_md.unpacked_files
        extracted_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / extracted_fn
        assert extracted_fn_abs.exists()
        with open(extracted_fn_abs,"rb") as f:
            assert f.read(2) == b'\x01\xda'


def test_unpack_different_filetypes(scan_environment):
    testfile = testdir_base / 'testdata' / 'download'/ 'archivers' / 'cpio' / 'initramfs.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open(open_file=False) as opened_md:
        p = CpioNewAsciiUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
        log.debug(f'--> info = {opened_md.info}')

    with reopen_md(md).open(open_file=False) as unpacked_md:
        unpacked_fn = unpacked_md.unpacked_path(pathlib.Path('etc'))
        unpacked_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / unpacked_fn
        assert unpacked_fn_abs.is_dir()

        # check if /linuxrc is a symlink to bin/busybox
        unpacked_fn = unpacked_md.unpacked_path(pathlib.Path('linuxrc'))
        unpacked_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / unpacked_fn
        assert unpacked_fn_abs.is_symlink()
        assert unpacked_fn_abs.resolve().name == 'busybox'
        assert unpacked_fn_abs.resolve().parent.name == 'bin'
        assert unpacked_fn in unpacked_md.unpacked_symlinks

        # check if device /dev/zero is skipped
        unpacked_fn = md.unpacked_path(pathlib.Path('/dev/zero'))
        unpacked_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / unpacked_fn
        assert not unpacked_fn_abs.exists()
        assert unpacked_fn not in md.unpacked_files
        assert unpacked_fn not in md.unpacked_symlinks
    

def test_cpio_with_absolute_path(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-absolute-path.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open('rb') as opened_md:
        p = CpioNewAsciiUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        unpacked_fn = unpacked_md.unpacked_path(pathlib.Path('/e/t.sgi'))
        unpacked_fn_abs = pathlib.Path(scan_environment.unpackdirectory) / unpacked_fn
        assert unpacked_fn_abs.exists()
        with unpacked_md.md_for_unpacked_path(unpacked_fn).open(open_file=False) as sub_md:
            assert sub_md.info.get('labels', set()) == set()


def test_load_cpio_with_multiple_files_portable(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-old-multiple-files.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open('rb') as opened_md:
        p = CpioPortableAsciiUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        assert len(unpacked_md.unpacked_files) == 2
        up1 = unpacked_md.unpacked_path(pathlib.Path('example.hex'))
        up2 = unpacked_md.unpacked_path(pathlib.Path('example.txt'))
        assert set(unpacked_md.unpacked_files.keys()) == set([up1,up2])
        assert (scan_environment.unpackdirectory / up1). exists()
        assert (scan_environment.unpackdirectory / up2). exists()
        s1 = (scan_environment.unpackdirectory / up1).open('rb').read()
        s2 = (scan_environment.unpackdirectory / up2).open('rb').read()
        assert s1 == s2


def test_load_cpio_with_multiple_files_crc(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-crc-multiple-files.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open('rb') as opened_md:
        p = CpioNewCrcUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        assert len(unpacked_md.unpacked_files) == 2
        up1 = unpacked_md.unpacked_path(pathlib.Path('example.hex'))
        up2 = unpacked_md.unpacked_path(pathlib.Path('example.txt'))
        assert set(unpacked_md.unpacked_files.keys()) == set([up1,up2])
        assert (scan_environment.unpackdirectory / up1). exists()
        assert (scan_environment.unpackdirectory / up2). exists()
        s1 = (scan_environment.unpackdirectory / up1).open('rb').read()
        s2 = (scan_environment.unpackdirectory / up2).open('rb').read()
        assert s1 == s2


def test_load_cpio_with_multiple_files_new_ascii(scan_environment):
    testfile = testdir_base / 'testdata' / 'unpackers' / 'cpio' / 'test-new-multiple-files.cpio'
    md = create_meta_directory_for_path(scan_environment, testfile, True)
    with md.open('rb') as opened_md:
        p = CpioNewAsciiUnpackParser(opened_md, 0)
        p.parse_from_offset()
        p.write_info(opened_md)
        for _ in p.unpack(opened_md): pass
    with reopen_md(md).open() as unpacked_md:
        assert len(unpacked_md.unpacked_files) == 2
        up1 = unpacked_md.unpacked_path(pathlib.Path('example.hex'))
        up2 = unpacked_md.unpacked_path(pathlib.Path('example.txt'))
        assert set(unpacked_md.unpacked_files.keys()) == set([up1,up2])
        assert (scan_environment.unpackdirectory / up1). exists()
        assert (scan_environment.unpackdirectory / up2). exists()
        s1 = (scan_environment.unpackdirectory / up1).open('rb').read()
        s2 = (scan_environment.unpackdirectory / up2).open('rb').read()
        assert s1 == s2

# Following archive formats are supported: binary, old ASCII, new ASCII, crc, HPUX binary, HPUX old ASCII, old tar, and POSIX.1 tar.

