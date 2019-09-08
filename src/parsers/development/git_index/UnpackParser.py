
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_git_index

class GitIndexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DIRC')
    ]
    pretty_name = 'git_index'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_git_index(fileresult, scan_environment, offset, unpack_dir)

