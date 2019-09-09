
import os
from UnpackParser import UnpackParser
from bangtext import unpack_python_pkginfo

class PythonPkginfoUnpackParser(UnpackParser):
    extensions = ['.pkginfo']
    signatures = [
    ]
    pretty_name = 'pkginfo'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_python_pkginfo(fileresult, scan_environment, offset, unpack_dir)

