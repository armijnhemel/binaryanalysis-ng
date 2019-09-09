
import os
from UnpackParser import UnpackParser
from bangtext import unpack_ini

class IniUnpackParser(UnpackParser):
    extensions = ['.ini']
    signatures = [
    ]
    pretty_name = 'ini'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ini(fileresult, scan_environment, offset, unpack_dir)

