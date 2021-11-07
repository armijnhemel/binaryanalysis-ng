
import os
from bang.UnpackParser import WrappedUnpackParser
from bangunpack import unpack_git_index

class GitIndexUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'DIRC')
    ]
    pretty_name = 'git_index'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_git_index(fileresult, scan_environment, offset, unpack_dir)

