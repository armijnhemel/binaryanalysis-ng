
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_python_pkginfo

class PythonPkginfoUnpackParser(WrappedUnpackParser):
    extensions = ['.pkginfo']
    signatures = [
    ]
    pretty_name = 'pkginfo'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_python_pkginfo(fileresult, scan_environment, offset, unpack_dir)

