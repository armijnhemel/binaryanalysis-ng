
import os
from UnpackParser import WrappedUnpackParser
from bangfilescans import unpack_java_manifest

class JavaManifestUnpackParser(WrappedUnpackParser):
    extensions = ['manifest.mf', '.sf']
    signatures = [
    ]
    pretty_name = 'javamanifest'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_java_manifest(fileresult, scan_environment, offset, unpack_dir)

