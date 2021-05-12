
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_group

class GroupUnpackParser(WrappedUnpackParser):
    extensions = ['group']
    signatures = [
    ]
    pretty_name = 'group'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_group(fileresult, scan_environment, offset, unpack_dir)

