
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_dds

class DdsUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'DDS')
    ]
    pretty_name = 'dds'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dds(fileresult, scan_environment, offset, unpack_dir)

