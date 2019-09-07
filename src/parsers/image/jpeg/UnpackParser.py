
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_jpeg

class JpegUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xff\xd8')
    ]
    pretty_name = 'jpeg'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_jpeg(fileresult, scan_environment, offset, unpack_dir)

