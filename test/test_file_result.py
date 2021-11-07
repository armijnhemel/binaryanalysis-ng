from .util import *

def test_fileresult_has_correct_filenames(scan_environment):
    relative_path = pathlib.Path("a/b/c.txt")
    full_path = pathlib.Path(scan_environment.unpackdirectory) / relative_path
    fr = fileresult(scan_environment.unpackdirectory, relative_path, set(), calculate_size=False)
    d = fr.get()
    assert fr.parent_path == relative_path.parent
    # assert fr.relpath == relative_path
    assert fr.filename == relative_path
    # assert d['fullfilename'] == str(full_path)
    assert d['filename'] == str(relative_path)
    assert d['parent'] == str(relative_path.parent)

def test_fileresult_unpack_directory_parent(scan_environment):
    relative_path = pathlib.Path("a/b/c.txt")
    fr = fileresult(scan_environment.unpackdirectory, relative_path, set(), calculate_size=False)
    assert fr.get_unpack_directory_parent() == relative_path
    assert 'TODO' == None

def test_fileresult_unpack_directory_parent_top(scan_environment):
    relative_path = pathlib.Path("a/b/c.txt")
    fr = fileresult(None, relative_path, set(), calculate_size=False)
    assert fr.get_unpack_directory_parent() == relative_path
    assert 'TODO' == None

