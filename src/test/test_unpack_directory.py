from .util import *
from unpack_directory import UnpackDirectory
from FileResult import FileResult


def test_create_unpack_directory_for_root_file(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, True)
    assert not ud.path.is_absolute()
    assert ud.path.name == ud.ROOT_PATH
    assert ud.abs_path == scan_environment.unpackdirectory / ud.path

def test_create_unpack_directory_for_unpacked_file(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    assert not ud.path.is_absolute()
    assert ud.path.name != ud.ROOT_PATH
    assert ud.abs_path == scan_environment.unpackdirectory / ud.path

def test_unpacked_path_absolute(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    p = pathlib.Path('/a/b/c')
    up = ud.unpacked_path(p)
    expected_up = ud.path / ud.ABS_UNPACK_DIR / p.relative_to('/')
    assert up == expected_up

def test_unpacked_path_relative(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    p = pathlib.Path('a/b/c')
    up = ud.unpacked_path(p)
    expected_up = ud.path / ud.REL_UNPACK_DIR / p
    assert up == expected_up

def test_write_info(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    data = { 'key': 'value' }
    ud.info = data
    assert (ud.abs_path / 'info.pkl').exists()

def test_read_info(scan_environment, tmpdir):
    data = { 'key': 'value' }
    unpack_path = pathlib.Path(tmpdir) / UnpackDirectory.ROOT_PATH
    info_path = unpack_path / 'info.pkl'
    info_path.parent.mkdir(parents=True, exist_ok=True)
    with info_path.open('wb') as f:
        pickle.dump(data, f)
    ud = UnpackDirectory.from_path(unpack_path.parent, unpack_path.name)
    assert ud.info == data

def test_write_relative_file(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    fpath = pathlib.Path('some/where/here.txt')
    data = b'hello!'
    up = ud.write_file(fpath, data)
    expected_path = ud.path / ud.REL_UNPACK_DIR / fpath
    expected_abs_path = ud.abs_path / ud.REL_UNPACK_DIR / fpath
    assert expected_abs_path.exists()
    assert expected_abs_path.open('rb').read() == data
    assert up == expected_path

def test_write_absolute_file(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    fpath = pathlib.Path('/some/where/here.txt')
    data = b'hello!'
    up = ud.write_file(fpath, data)
    expected_path = ud.path / ud.ABS_UNPACK_DIR / fpath.relative_to('/')
    expected_abs_path = ud.abs_path / ud.ABS_UNPACK_DIR / fpath.relative_to('/')
    assert expected_abs_path.exists()
    assert expected_abs_path.open('rb').read() == data
    assert up == expected_path

def test_make_relative_directory(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    dpath = pathlib.Path('some/where/here')
    up = ud.mkdir(dpath)
    expected_path = ud.path / ud.REL_UNPACK_DIR / dpath
    expected_abs_path = ud.abs_path / ud.REL_UNPACK_DIR / dpath
    assert expected_abs_path.exists()
    assert expected_abs_path.is_dir()
    assert up == expected_path

def test_make_absolute_directory(scan_environment):
    ud = UnpackDirectory(scan_environment.unpackdirectory, None, False)
    dpath = pathlib.Path('/some/where/here')
    up = ud.mkdir(dpath)
    expected_path = ud.path / ud.ABS_UNPACK_DIR / dpath.relative_to('/')
    expected_abs_path = ud.abs_path / ud.ABS_UNPACK_DIR / dpath.relative_to('/')
    assert expected_abs_path.exists()
    assert expected_abs_path.is_dir()
    assert up == expected_path

