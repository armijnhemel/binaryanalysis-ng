
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_jpeg

class JpegUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\xff\xd8')
    ]
    pretty_name = 'jpeg'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_jpeg(fileresult, scan_environment, offset, unpack_dir)

