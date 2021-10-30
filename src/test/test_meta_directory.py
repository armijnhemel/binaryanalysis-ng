from .util import *
from meta_directory import MetaDirectory
from FileResult import FileResult


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
    assert md.abs_md_path == scan_environment.unpackdirectory / md.path

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
    p = pathlib.Path('a/b/c')
    with md.open(open_file=False) as opened_md:
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
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    data = { 'key': 'value' }
    md.info = data
    assert (md.abs_path / 'info.pkl').exists()

def test_read_info(scan_environment, tmpdir):
    data = { 'key': 'value' }
    unpack_path = pathlib.Path(tmpdir) / MetaDirectory.ROOT_PATH
    info_path = unpack_path / 'info.pkl'
    info_path.parent.mkdir(parents=True, exist_ok=True)
    with info_path.open('wb') as f:
        pickle.dump(data, f)
    md = MetaDirectory.from_path(unpack_path.parent, unpack_path.name)
    assert md.info == data

def test_write_relative_file(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    fpath = pathlib.Path('some/where/here.txt')
    data = b'hello!'
    up = md.write_file(fpath, data)
    expected_path = md.path / md.REL_UNPACK_DIR / fpath
    expected_abs_path = md.abs_path / md.REL_UNPACK_DIR / fpath
    assert expected_abs_path.exists()
    assert expected_abs_path.open('rb').read() == data
    assert up == expected_path

def test_write_absolute_file(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    fpath = pathlib.Path('/some/where/here.txt')
    data = b'hello!'
    up = md.write_file(fpath, data)
    expected_path = md.path / md.ABS_UNPACK_DIR / fpath.relative_to('/')
    expected_abs_path = md.abs_path / md.ABS_UNPACK_DIR / fpath.relative_to('/')
    assert expected_abs_path.exists()
    assert expected_abs_path.open('rb').read() == data
    assert up == expected_path

def test_make_relative_directory(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    dpath = pathlib.Path('some/where/here')
    up = md.mkdir(dpath)
    expected_path = md.path / md.REL_UNPACK_DIR / dpath
    expected_abs_path = md.abs_path / md.REL_UNPACK_DIR / dpath
    assert expected_abs_path.exists()
    assert expected_abs_path.is_dir()
    assert up == expected_path

def test_make_absolute_directory(scan_environment):
    md = MetaDirectory(scan_environment.unpackdirectory, None, False)
    dpath = pathlib.Path('/some/where/here')
    up = md.mkdir(dpath)
    expected_path = md.path / md.ABS_UNPACK_DIR / dpath.relative_to('/')
    expected_abs_path = md.abs_path / md.ABS_UNPACK_DIR / dpath.relative_to('/')
    assert expected_abs_path.exists()
    assert expected_abs_path.is_dir()
    assert up == expected_path

