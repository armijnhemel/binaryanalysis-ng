
import os
from UnpackParser import UnpackParser
from bangtext import unpack_trans_tbl

class TransTblUnpackParser(UnpackParser):
    extensions = ['trans.tbl']
    signatures = [
    ]
    pretty_name = 'trans.tbl'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_trans_tbl(fileresult, scan_environment, offset, unpack_dir)

