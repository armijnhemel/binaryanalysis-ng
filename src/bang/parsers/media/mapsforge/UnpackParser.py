
import os
from bang.UnpackParser import WrappedUnpackParser
from bangmedia import unpack_mapsforge

class MapsforgeUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'mapsforge binary OSM')
    ]
    pretty_name = 'mapsforge'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_mapsforge(fileresult, scan_environment, offset, unpack_dir)

