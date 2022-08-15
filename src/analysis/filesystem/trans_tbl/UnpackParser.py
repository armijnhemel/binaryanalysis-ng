
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_trans_tbl

class TransTblUnpackParser(WrappedUnpackParser):
    extensions = ['trans.tbl']
    signatures = [
    ]
    pretty_name = 'trans.tbl'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_trans_tbl(fileresult, scan_environment, offset, unpack_dir)

