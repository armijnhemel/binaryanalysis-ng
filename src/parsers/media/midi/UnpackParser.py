
import os
from UnpackParser import WrappedUnpackParser
from bangmedia import unpack_midi

class MidiUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'MThd')
    ]
    pretty_name = 'midi'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_midi(fileresult, scan_environment, offset, unpack_dir)

