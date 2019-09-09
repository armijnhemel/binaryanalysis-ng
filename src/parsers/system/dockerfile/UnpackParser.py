
import os
from UnpackParser import UnpackParser
from bangtext import unpack_dockerfile

class DockerfileUnpackParser(UnpackParser):
    extensions = ['dockerfile', '.dockerfile']
    signatures = [
    ]
    pretty_name = 'dockerfile'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dockerfile(fileresult, scan_environment, offset, unpack_dir)

