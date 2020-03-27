
import os
from UnpackParser import WrappedUnpackParser
from bangtext import unpack_dockerfile

class DockerfileUnpackParser(WrappedUnpackParser):
    extensions = ['dockerfile', '.dockerfile']
    signatures = [
    ]
    pretty_name = 'dockerfile'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dockerfile(fileresult, scan_environment, offset, unpack_dir)

