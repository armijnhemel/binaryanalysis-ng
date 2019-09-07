
import os
from UnpackParser import UnpackParser
from bangmedia import unpack_midi

class MidiUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'MThd')
    ]
    pretty_name = 'midi'

    def parse_and_unpack(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_midi(fileresult, scan_environment, offset, unpack_dir)

