from UnpackManager import UnpackManager
from .util import *

testdata_dir = testdir_base / 'testdata'

def test_create_unpack_manager(scan_environment):
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    assert unpack_manager.needs_unpacking() == True
    assert unpack_manager.last_unpacked_offset() == -1

def test_mark_file_to_skip(scan_environment):
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    unpack_manager.set_needs_unpacking(False)
    assert unpack_manager.needs_unpacking() == False

def test_mark_file_report_only(scan_environment):
    file_size = 100
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    unpack_manager.set_needs_unpacking(False)
    unpack_manager.set_last_unpacked_offset(file_size)
    unpack_manager.append_unpacked_range(0, file_size)
    assert unpack_manager.unpacked_range() == [ (0, file_size) ]
    assert unpack_manager.last_unpacked_offset() == file_size


def test_check_for_valid_extension(scan_environment):
    pass
# TODO: this violates the FileResult API, which requires a relative path!
def create_tmp_fileresult(path_abs, content):
    with open(path_abs, 'wb') as f:
        f.write(content)
    fileresult = FileResult(None, path_abs, set())
    fileresult.set_filesize(path_abs.stat().st_size)
    return fileresult


def test_try_unpack_for_extension_success(scan_environment):
    fn = pathlib.Path("test.ex1")
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, b"A"*70)
    unpack_parser = UnpackParserExtractEx1
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    unpack_result = unpack_manager.try_unpack_file_for_extension(fileresult, scan_environment, '.ex1', unpack_parser)
    print(dir(unpack_result))
    assert len(unpack_result.unpacked_files) == 2
    assert unpack_result.unpacked_files[0].filename.name == "ex1_first"
    assert unpack_result.unpacked_files[1].filename.name == "ex1_second"
    assertUnpackedPathExists(scan_environment, unpack_result.unpacked_files[0].filename)
    assertUnpackedPathExists(scan_environment, unpack_result.unpacked_files[1].filename)

def test_try_unpack_for_extension_carve(scan_environment):
    fn = pathlib.Path("test.ex1")
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, b"A"*70)
    unpack_parser = UnpackParserExtractEx1Carve
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    unpack_result = unpack_manager.try_unpack_file_for_extension(fileresult, scan_environment, '.ex1', unpack_parser)
    assert len(unpack_result.unpacked_files) == 3
    assert unpack_result.unpacked_files[0].filename.name == "ex1_first"
    assert unpack_result.unpacked_files[1].filename.name == "ex1_second"
    assert unpack_result.unpacked_files[2].filename.name == "unpacked.ex1_extract_carve"
    assertUnpackedPathExists(scan_environment, unpack_result.unpacked_files[0].filename)
    assertUnpackedPathExists(scan_environment, unpack_result.unpacked_files[1].filename)
    assertUnpackedPathExists(scan_environment, unpack_result.unpacked_files[2].filename)

def test_try_unpack_for_extension_fail(scan_environment):
    fn = pathlib.Path("test.ex1")
    fileresult = create_tmp_fileresult(scan_environment.temporarydirectory / fn, b"A"*70)
    unpack_parser = UnpackParserExtractEx1Fail
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    with pytest.raises(UnpackParserException):
        unpack_result = unpack_manager.try_unpack_file_for_extension(fileresult, scan_environment, '.ex1', unpack_parser)

    # TODO: currently scanjob takes care of removing the unpack directory, but unpackmanager should perhaps do this
    # assert not (scan_environment.unpackdirectory / unpack_manager.dataunpackdirectory).exists()
    assert os.listdir(scan_environment.unpackdirectory / unpack_manager.dataunpackdirectory) == []



def test_file_reading(scan_environment):
    unpack_manager = UnpackManager(scan_environment.unpackdirectory)
    # unpack_manager.open_scanfile_with_memoryview(...)
    # unpack_manager.seek_to_last_unpacked_offset()
    # unpack_manager.read_chunk_from_scanfile()
    # unpack_manager.close_scanfile()
    # assert right chunk was read
    # assert

def test_check_for_signatures_success(scan_environment):
    # unpack_manager.make_data_unpack_directory?
    # unpack_manager.try_unpack_file_for_signatures(...)
    # case1: success
    # assert file is extracted, offsets match
    pass

def test_check_for_signatures_fail(scan_environment):
    # unpack_manager.try_unpack_file_for_signatures(...)
    # case2: failure
    # no extracted files, no offset update etc
    pass

def test_offsets_overlap(scan_environment):
    # unpack_manager.offset_overlaps_with_unpacked_data
    pass

def test_carve_file_data(scan_environment):
    # see synthesize_file
    pass

def test_check_entire_file(scan_environment):
    pass


