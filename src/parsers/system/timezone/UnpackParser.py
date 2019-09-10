
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_timezone

class TimezoneUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'TZif')
    ]
    pretty_name = 'timezone'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_timezone(fileresult, scan_environment, offset, unpack_dir)

