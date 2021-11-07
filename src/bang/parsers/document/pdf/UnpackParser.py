
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_pdf

class PdfUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'%PDF-')
    ]
    pretty_name = 'pdf'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_pdf(fileresult, scan_environment, offset, unpack_dir)

