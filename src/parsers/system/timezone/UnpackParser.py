
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_timezone

class TimezoneUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'TZif')
    ]
    pretty_name = 'timezone'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_timezone(fileresult, scan_environment, offset, unpack_dir)

