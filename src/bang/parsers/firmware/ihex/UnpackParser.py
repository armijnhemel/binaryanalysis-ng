
import os
import pathlib
from bang.UnpackParser import UnpackParser, check_condition
from bang.log import log
from bangtext import unpack_ihex

def parse_ihex_line(line):
    log.debug(f'parse_ihex_line: {line!r}, {len(line)=}')
    if len(line) < 11 or len(line) % 2 == 0:
        # invalid format
        return None, None
    bytes_count = int.from_bytes(bytes.fromhex(line[1:3].decode('ascii')), byteorder='big')
    log.debug(f'parse_ihex_line: {bytes_count=}')
    if len(line) < 3 + bytes_count + 2:
        # invalid format
        return None, None
    record_type = int.from_bytes(bytes.fromhex(line[7:9].decode('ascii')), byteorder='big')
    log.debug(f'parse_ihex_line: {record_type=}')
    if record_type > 5:
        # invalid format
        return None, None
    if record_type == 0:
        ihex_data = bytes.fromhex(line[9:9+bytes_count*2].decode('ascii'))
        return 0, ihex_data
    if record_type == 1:
        return 1, ''


class IhexUnpackParser(UnpackParser):
    extensions = ['.hex', '.ihex']
    signatures = [ ]
    scan_if_featureless = True
    pretty_name = 'ihex'

    def parse(self):
        self.unpacked_size = 0
        self.data = []
        valid_file = False
        used_record_types = set()

        line = self.infile.readline()
        while line != b'':
            log.debug(f'ihex_parse: {line!r}')
            sline = line.strip()
            if line.startswith(b':'):
                try:
                    record_type, line_data = parse_ihex_line(sline)
                    used_record_types.add(record_type)
                    if record_type == 0:
                        self.data.append(line_data)
                        self.unpacked_size += len(line)
                    elif record_type == 1:
                        valid_file = True
                        self.unpacked_size += len(line)
                        break
                    else:
                        # invalid format
                        break
                except ValueError as e:
                    log.debug(f'ihex_parse: exception {e}')
                    # invalid format
                    break
            elif line.startswith(b'#'):
                self.unpacked_size += len(line)
            else:
                # invalid format
                break
            line = self.infile.readline()
        
        # Exception or no end of data record causes an Invalid IHEX file error
        check_condition(valid_file,'Invalid IHEX file')
        check_condition(not (
            (4 in used_record_types or 5 in used_record_types) and 3 in used_record_types
            ), 'Incompatible record types combined')

    def unpack(self, to_meta_directory):
        path = pathlib.Path('unpacked-from-ihex')
        with to_meta_directory.unpack_regular_file(path) as (unpacked_md, f):
            f.write(b''.join(self.data))
            yield unpacked_md

    labels = [ 'ihex' ]
    metadata = {}

