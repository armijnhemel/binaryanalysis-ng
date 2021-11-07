
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_psd

class PsdUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'8BPS')
    ]
    pretty_name = 'psd'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_psd(fileresult, scan_environment, offset, unpack_dir)

