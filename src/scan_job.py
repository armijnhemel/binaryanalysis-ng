import os
from unpack_directory import *

class ScanJob:
    def __init__(self, path):
        self._path = path
        self._unpack_directory = None

    def set_scan_environment(self, scan_environment):
        self.scan_environment = scan_environment

    @property
    def unpack_directory(self):
        if self._unpack_directory is None:
            self._unpack_directory = UnpackDirectory.from_ud_path(self.scan_environment.unpackdirectory, self._path)
        return self._unpack_directory

def is_unscannable(path):
    return not path.is_file()
    # return path.is_dir() or path.is_fifo() or path.is_socket() or path.is_block_device() or path.is_char_device() or path.is_symlink()


def check_by_extension(path_unpack_directory):
    for unpack_parser in scan_extensions(path_unpack_directory.path):
        # this will give all unpack_parsers that match the extension
        try:
            unpack_parser.parse(path_unpack_directory.path, 0)
            unpack_parser.unpack(path_unpack_directory)
            # TODO: update info, not overwite
            unpack_parser.write_info(path_unpack_directory)
            yield path_unpack_directory
            # take the first working parser
            return
        except UnpackParserException as e:
            pass


def check_by_signature(path_unpack_directory):
    # find offsets
    for offset, unpack_parser in scan_signatures(path_unpack_directory.path):
        # scan_signatures will give a SynthesizingParser for synthesized files
        try:
            unpack_parser.parse(path_unpack_directory.path, offset)
            if offset == 0 and unpack_parser.length == path_unpack_directory.length:
                # no need to extract a subfile
                unpack_parser.unpack(path_unpack_directory)
                # TODO: update info, not overwite
                unpack_parser.write_info(path_unpack_directory)
                yield path_unpack_directory
            else:
                path_unpack_directory.extract_data(offset, unpack_parser.length, data)
                ud = UnpackDirectory(...)
                unpack_parser.unpack(ud)
                # TODO: update info, not overwite
                unpack_parser.write_info(ud)
                yield ud
        except UnpackParserException as e:
            pass

def process_job(scan_environment, scanjob):
    # scanjob has: path, unpack_directory object and context
    unpack_directory = scanjob.unpack_directory

    if is_unscannable(unpack_directory.file_path):
        return

    if scanjob.context_is_padding(unpack_directory.context):
        return

    for r in check_by_extension(unpack_directory):
        # r is an unpack_directory
        # unpackdirectory has files to unpack (i.e. for archives)
        # or extra data (which needs carving)
        for up in r.unpacked_files:
            # queue up
            pass
        for extra in r.extra_data:
            # queue extra
            pass

        for r in check_by_signature(unpack_directory):
            # if r is synthesized, queue it for extra checks?
            for up in r.unpacked_files:
                # queue
                pass
            # for extra in r.extra_data: pass # no extra data if scanning by sig

def process_jobs(scan_environment):
    # code smell, should not be needed if unpackparsers behave
    os.chdir(scan_environment.unpackdirectory)

    while True:
        try:
            # TODO: check if timeout long enough
            scanjob = scan_environment.scanfilequeue.get(timeout=86400)
        except scan_environment.scanfilequeue.Empty as e:
            break
        scanjob.set_scan_environment(scan_environment)
        process_job(scan_environment, scanjob)
        scan_environment.scanfilequeue.task_done()


