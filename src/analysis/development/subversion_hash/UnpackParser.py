
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_subversion_hash

class SubversionHashUnpackParser(WrappedUnpackParser):
    extensions = ['wcprops']
    signatures = [
    ]
    pretty_name = 'subversion_hash'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_subversion_hash(fileresult, scan_environment, offset, unpack_dir)

