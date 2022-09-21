from util import *
from bang.meta_directory import MetaDirectory


def test_create_unpack_directory_for_root_file(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, True)
    md.file_path = '/dev/null'
    assert not md.md_path.is_absolute()
    assert md.md_path.name == md.ROOT_PATH
    # assert (scan_environment.unpackdirectory / md.md_path).exists()
    # assert (scan_environment.unpackdirectory / md.md_path).is_dir()

def test_create_unpack_directory_for_unpacked_file(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    md.file_path = 'uuid/rel/file'
    assert not md.md_path.is_absolute()
    assert md.md_path.name != md.ROOT_PATH
    assert md.abs_md_path == scan_environment.unpackdirectory / md.md_path

def test_unpacked_path_absolute(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    md.file_path = 'uuid/rel/file'
    p = pathlib.Path('/a/b/c')
    up = md.unpacked_path(p)
    expected_up = md.md_path / md.ABS_UNPACK_DIR / p.relative_to('/')
    assert up == expected_up

def test_unpacked_path_relative(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    md.file_path = 'uuid/rel/file'
    p = pathlib.Path('a/b/c')
    up = md.unpacked_path(p)
    expected_up = md.md_path / md.REL_UNPACK_DIR / p
    assert up == expected_up

def test_unpack_paths(scan_environment):
    fn = pathlib.Path('metadirectory_test.bin')
    create_test_file(scan_environment, fn, b'\xff'*299 + b'A')
    md = create_meta_directory_for_path(scan_environment, fn, True)
    with md.open(open_file=False) as opened_md:
        p = pathlib.Path('a/b/c')
        with opened_md.unpack_regular_file(p) as (unpacked_md, f):
            f.write(b'hello')

    with reopen_md(md).open() as md2:
        up = md2.unpacked_path(p)
        assert up in md2.unpacked_files
        p_abs = md2.meta_root / up
        assert p_abs.exists()
        with p_abs.open('rb') as f:
            assert f.read() == b'hello'
        sub_md = md2.unpacked_md(p)
        assert sub_md.file_path == up


def test_write_info(scan_environment):
    fn = pathlib.Path('metadirectory_test.bin')
    create_test_file(scan_environment, fn, b'\xff'*299 + b'A')
    md = create_meta_directory_for_path(scan_environment, fn, True)
    with md.open(open_file=False) as opened_md:
        data = { 'key': 'value' }
        opened_md.info = data
    with reopen_md(md).open() as reloaded_md:
        assert reloaded_md.info == data

