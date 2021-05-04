
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_dds

class DdsUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'DDS ')
    ]
    pretty_name = 'dds'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dds(fileresult, scan_environment, offset, unpack_dir)

