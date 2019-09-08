
import os
from UnpackParser import UnpackParser
from bangunpack import unpack_qcdt

class QcdtUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'QCDT')
    ]
    pretty_name = 'qcdt'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_qcdt(fileresult, scan_environment, offset, unpack_dir)

