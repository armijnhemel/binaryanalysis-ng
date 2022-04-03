
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_ics

class IcsUnpackParser(WrappedUnpackParser):
    extensions = ['.ics']
    signatures = [
    ]
    pretty_name = 'ics'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_ics(fileresult, scan_environment, offset, unpack_dir)

