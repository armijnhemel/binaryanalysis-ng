
import os
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_qcdt

class QcdtUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'QCDT')
    ]
    pretty_name = 'qcdt'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_qcdt(fileresult, scan_environment, offset, unpack_dir)

