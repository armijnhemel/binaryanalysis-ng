
import os
from UnpackParser import UnpackParser
from bangtext import unpack_java_manifest

class JavaManifestUnpackParser(UnpackParser):
    extensions = ['manifest.mf', '.sf']
    signatures = [
    ]
    pretty_name = 'javamanifest'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_manifest(fileresult, scan_environment, offset, unpack_dir)

