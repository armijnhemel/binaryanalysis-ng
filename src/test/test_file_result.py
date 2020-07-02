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

