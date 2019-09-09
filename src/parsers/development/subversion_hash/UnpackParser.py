
import os
from UnpackParser import UnpackParser
from bangtext import unpack_subversion_hash

class SubversionHashUnpackParser(UnpackParser):
    extensions = ['wcprops']
    signatures = [
    ]
    pretty_name = 'subversion_hash'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_subversion_hash(fileresult, scan_environment, offset, unpack_dir)

