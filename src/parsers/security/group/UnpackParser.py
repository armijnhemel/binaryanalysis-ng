
import os
from UnpackParser import UnpackParser
from bangtext import unpack_group

class GroupUnpackParser(UnpackParser):
    extensions = ['group']
    signatures = [
    ]
    pretty_name = 'group'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_group(fileresult, scan_environment, offset, unpack_dir)

