# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# BANG is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# BANG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License, version 3, along with BANG.  If not, see
# <http://www.gnu.org/licenses/>
#
# Copyright Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only


import os
import hashlib
import zlib
import tlsh
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_dex

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import dex

# Opcodes for the various versions. The format is:
#
#   {opcode: code_units}
#
# where code_units is 16 bit (2 bytes) and includes the opcode itself
# The names of the instructions are not very interesting here, but
# the bytecode needs to be parsed to extract the right strings.
#
# Not every opcode is in every version.

DEX_035_OPCODES = {0x00: 1, 0x01: 1, 0x02: 2, 0x03: 3, 0x04: 1,
                   0x05: 2, 0x06: 3, 0x07: 1, 0x08: 2, 0x09: 3,
                   0x0a: 1, 0x0b: 1, 0x0c: 1, 0x0d: 1, 0x0e: 1,
                   0x0f: 1, 0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2,
                   0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3, 0x18: 5,
                   0x19: 2, 0x1a: 2, 0x1b: 3, 0x1c: 2, 0x1d: 1,
                   0x1e: 1, 0x1f: 2, 0x20: 2, 0x21: 1, 0x22: 2,
                   0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3, 0x27: 1,
                   0x28: 1, 0x29: 2, 0x2a: 3, 0x2b: 3, 0x2c: 3,
                   0x2d: 2, 0x2e: 2, 0x2f: 2, 0x30: 2, 0x31: 2,
                   0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2,
                   0x37: 2, 0x38: 2, 0x39: 2, 0x3a: 2, 0x3b: 2,
                   0x3c: 2, 0x3d: 2, 0x44: 2, 0x45: 2, 0x46: 2,
                   0x47: 2, 0x48: 2, 0x49: 2, 0x4a: 2, 0x4b: 2,
                   0x4c: 2, 0x4d: 2, 0x4e: 2, 0x4f: 2, 0x50: 2,
                   0x51: 2, 0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2,
                   0x56: 2, 0x57: 2, 0x58: 2, 0x59: 2, 0x5a: 2,
                   0x5b: 2, 0x5c: 2, 0x5d: 2, 0x5e: 2, 0x5f: 2,
                   0x60: 2, 0x61: 2, 0x62: 2, 0x62: 2, 0x63: 2,
                   0x64: 2, 0x65: 2, 0x66: 2, 0x67: 2, 0x68: 2,
                   0x69: 2, 0x6a: 2, 0x6b: 2, 0x6c: 2, 0x6d: 2,
                   0x6e: 3, 0x6f: 3, 0x70: 3, 0x71: 3, 0x72: 3,
                   0x74: 3, 0x75: 3, 0x76: 3, 0x77: 3, 0x78: 3,
                   0x7b: 1, 0x7c: 1, 0x7d: 1, 0x7e: 1, 0x7e: 1,
                   0x7f: 1, 0x80: 1, 0x81: 1, 0x82: 1, 0x83: 1,
                   0x84: 1, 0x85: 1, 0x86: 1, 0x87: 1, 0x88: 1,
                   0x89: 1, 0x8a: 1, 0x8b: 1, 0x8c: 1, 0x8d: 1,
                   0x8e: 1, 0x8f: 1, 0x90: 2, 0x91: 2, 0x92: 2,
                   0x93: 2, 0x94: 2, 0x95: 2, 0x96: 2, 0x97: 2,
                   0x98: 2, 0x99: 2, 0x9a: 2, 0x9b: 2, 0x9c: 2,
                   0x9d: 2, 0x9e: 2, 0x9f: 2, 0xa0: 2, 0xa1: 2,
                   0xa2: 2, 0xa3: 2, 0xa4: 2, 0xa5: 2, 0xa6: 2,
                   0xa7: 2, 0xa8: 2, 0xa9: 2, 0xaa: 2, 0xab: 2,
                   0xac: 2, 0xad: 2, 0xae: 2, 0xaf: 2, 0xb0: 1,
                   0xb1: 1, 0xb2: 1, 0xb3: 1, 0xb4: 1, 0xb5: 1,
                   0xb6: 1, 0xb7: 1, 0xb8: 1, 0xb9: 1, 0xba: 1,
                   0xbb: 1, 0xbc: 1, 0xbd: 1, 0xbe: 1, 0xbf: 1,
                   0xc0: 1, 0xc1: 1, 0xc2: 1, 0xc3: 1, 0xc4: 1,
                   0xc5: 1, 0xc6: 1, 0xc7: 1, 0xc8: 1, 0xc9: 1,
                   0xca: 1, 0xcb: 1, 0xcc: 1, 0xcd: 1, 0xce: 1,
                   0xcf: 1, 0xd0: 2, 0xd1: 2, 0xd2: 2, 0xd3: 2,
                   0xd4: 2, 0xd5: 2, 0xd6: 2, 0xd7: 2, 0xd8: 2,
                   0xd9: 2, 0xda: 2, 0xdb: 2, 0xdc: 2, 0xdd: 2,
                   0xde: 2, 0xdf: 2, 0xe0: 2, 0xe1: 2, 0xe2: 2 }

# see https://android.googlesource.com/platform/dalvik/+/android-4.4.2_r2/opcode-gen/bytecode.txt
DEX_037_OPCODES = {0xe3: 2, 0xe4: 2, 0xe5: 2, 0xe6: 2, 0xe7: 2,
                   0xe8: 2, 0xe9: 2, 0xea: 2, 0xeb: 2, #0xec: 0,
                   0xed: 2, 0xee: 3, 0xef: 3, 0xf0: 3, 0xf1: 1,
                   0xf2: 2, 0xf3: 2, 0xf4: 2, 0xf5: 2, 0xf6: 2,
                   0xf7: 2, 0xf8: 3, 0xf9: 3, 0xfa: 3, 0xfb: 3,
                   0xfc: 2, 0xfd: 2, 0xfe: 2,}

DEX_038_OPCODES = {0xfa: 4, 0xfb: 4, 0xfc: 3, 0xfd: 3}

DEX_039_OPCODES = {0xfe: 2, 0xff: 2}

# combine the opcodes. As Odex 037 contains Dex 035 files (with
# optimizations) also consider the Odex opcodes in Dex 035 files.
DEX_035 = DEX_035_OPCODES | DEX_037_OPCODES
DEX_037 = DEX_035_OPCODES | DEX_037_OPCODES
DEX_038 = DEX_035_OPCODES | DEX_037_OPCODES | DEX_038_OPCODES
DEX_039 = DEX_035_OPCODES | DEX_037_OPCODES | DEX_038_OPCODES | DEX_039_OPCODES

class DexUnpackParser(WrappedUnpackParser):
#class DexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'dex\n')
    ]
    pretty_name = 'dex'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dex(fileresult, scan_environment, offset, unpack_dir)

    def parse_bytecode(self, bytecode, opcode_version=None):
        # parse enough of the bytecode to be able to extract the strings
        if opcode_version == None:
            version_str = self.data.header.version_str
        else:
            version_str = opcode_version

        # select the correct opcodes
        if version_str == '035':
            opcodes = DEX_035
        elif version_str == '037':
            opcodes = DEX_037
        elif version_str == '038':
            opcodes = DEX_038
        elif version_str == '039':
            opcodes = DEX_039

        len_bytecode = len(bytecode)
        counter = 0
        string_ids = []
        while counter < len_bytecode:
            # read the first instruction
            opcode = bytecode[counter]

            # TODO: length sanity check

            # process the byte code to find strings. The interesting
            # instructions are:
            #
            # - const-string (0x1a)
            # - const-string/jumbo (0x1b)
            #
            # Some instructions contain extra data and they need to be
            # parsed separately and then be skipped.
            #
            # - fill-array-data (0x26)
            # - packed-switch (0x2b)
            # - sparse-switch (0x2c)
            if opcode == 0x1a:
                string_id = int.from_bytes(bytecode[counter+2:counter+4], byteorder='little')
                string_ids.append(string_id)
            elif opcode == 0x1b:
                string_id = int.from_bytes(bytecode[counter+2:counter+6], byteorder='little')
                string_ids.append(string_id)
            elif opcode == 0x00:
                # the payloads for fill-array-data, packed-switch and sparse-switch
                # use a pseudo opcode
                if bytecode[counter+1] == 1:
                    # packed-switch-payload
                    counter += opcodes[opcode] * 2

                    # number of entries in the table
                    size = int.from_bytes(bytecode[counter:counter+2], byteorder='little')
                    counter += 2
                    first_key = int.from_bytes(bytecode[counter:counter+4], byteorder='little')
                    counter += 4
                    # then the data
                    for k in range(0, size):
                        key = int.from_bytes(bytecode[counter:counter+4], byteorder='little')
                        counter += 4
                    continue
                elif bytecode[counter+1] == 2:
                    # sparse-switch-payload
                    counter += opcodes[opcode] * 2
                    size = int.from_bytes(bytecode[counter:counter+2], byteorder='little')
                    counter += 2

                    # keys
                    for k in range(0, size):
                        key = int.from_bytes(bytecode[counter:counter+4], byteorder='little')
                        counter += 4

                    # targets
                    for t in range(0, size):
                        target = int.from_bytes(bytecode[counter:counter+4], byteorder='little')
                        counter += 4
                    continue
                elif bytecode[counter+1] == 3:
                    # fill-array-data payload
                    counter += opcodes[opcode] * 2
                    element_width = int.from_bytes(bytecode[counter:counter+2], byteorder='little')
                    counter += 2

                    size = int.from_bytes(bytecode[counter:counter+4], byteorder='little')
                    counter += 4

                    # data
                    counter += size * element_width
                    continue

            counter += opcodes[opcode] * 2
        return string_ids

    def parse(self):
        filesize = self.fileresult.filesize
        try:
            self.data = dex.Dex.from_io(self.infile)
            computed_checksum = zlib.adler32(self.data.bytes_for_adler32)
            self.unpacked_size = self.data.header.file_size
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(self.data.header.checksum == computed_checksum,
                        "wrong Adler32")

        # check many offsets
        check_condition(self.data.header.string_ids_off + self.data.header.string_ids_size <= filesize,
                        "string_ids cannot be outside of file")
        check_condition(self.data.header.type_ids_off + self.data.header.type_ids_size <= filesize,
                        "type_ids cannot be outside of file")
        check_condition(self.data.header.proto_ids_off + self.data.header.proto_ids_size <= filesize,
                        "proto_ids cannot be outside of file")
        check_condition(self.data.header.field_ids_off + self.data.header.field_ids_size <= filesize,
                        "field_ids cannot be outside of file")
        check_condition(self.data.header.method_ids_off + self.data.header.method_ids_size <= filesize,
                        "method_ids cannot be outside of file")
        check_condition(self.data.header.class_defs_off + self.data.header.class_defs_size <= filesize,
                        "class_defs cannot be outside of file")
        check_condition(self.data.header.data_off + self.data.header.data_size <= filesize,
                        "data cannot be outside of file")
        check_condition(self.data.header.map_off <= filesize,
                        "map item cannot be outside of file")
        check_condition(self.data.header.map_off >= self.data.header.data_off,
                        "map item has to be inside data section")
        check_condition(self.data.header.map_off < self.data.header.data_off + self.data.header.data_size,
                        "map item has to be inside data section")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['dex', 'android']
        metadata = {}
        metadata['version'] = self.data.header.version_str
        metadata['classes'] = []

        for class_definition in self.data.class_defs:
            if class_definition.class_data is None:
                continue
            class_obj = {}
            class_obj['classname'] = class_definition.type_name[1:-1]
            class_obj['source'] = class_definition.sourcefile_name
            class_obj['methods'] = []

            # process direct methods
            method_id = 0
            for method in class_definition.class_data.direct_methods:
                if method.code is None:
                    continue

                # compute various hashes for the bytecode and store them
                hashes = {}
                sha256 = hashlib.sha256(method.code.insns).hexdigest()
                hashes['sha256'] = sha256
                tlsh_hash = tlsh.hash(method.code.insns)
                if tlsh_hash != 'TNULL':
                    hashes['tlsh'] = tlsh_hash
                else:
                    hashes['tlsh'] = None

                # extract the relevant strings from the bytecode and store them
                strings = []
                res = self.parse_bytecode(method.code.insns)
                if res != []:
                  for r in res:
                      strings.append(self.data.string_ids[r].value.data)

                method_id += method.method_idx_diff.value
                class_obj['methods'].append({'name': self.data.method_ids[method_id].method_name,
                                            'method_type': 'direct', 'bytecode_hashes': hashes,
                                            'strings': strings})
            # process virtual methods
            method_id = 0
            for method in class_definition.class_data.virtual_methods:
                if method.code is None:
                    continue

                # compute various hashes for the bytecode and store them
                hashes = {}
                sha256 = hashlib.sha256(method.code.insns).hexdigest()
                hashes['sha256'] = sha256
                tlsh_hash = tlsh.hash(method.code.insns)
                if tlsh_hash != 'TNULL':
                    hashes['tlsh'] = tlsh_hash
                else:
                    hashes['tlsh'] = None

                # extract the relevant strings from the bytecode and store them
                strings = []
                res = self.parse_bytecode(method.code.insns)
                if res != []:
                  for r in res:
                      strings.append(self.data.string_ids[r].value.data)

                method_id += method.method_idx_diff.value
                class_obj['methods'].append({'name': self.data.method_ids[method_id].method_name,
                                            'method_type': 'virtual', 'bytecode_hashes': hashes,
                                            'strings': strings})

            # process fields
            class_obj['fields'] = []
            field_id = 0
            for field in class_definition.class_data.static_fields:
                field_id += field.field_idx_diff.value
                field_type = self.data.field_ids[field_id].type_name
                if field_type.endswith(';'):
                    field_type = field_type[1:-1]
                class_type = self.data.field_ids[field_id].class_name
                if class_type.endswith(';'):
                    class_type = class_type[1:-1]
                class_obj['fields'].append({'name': self.data.field_ids[field_id].field_name,
                                            'type': field_type, 'class': class_type,
                                            'field_type': 'static'})
            field_id = 0
            for field in class_definition.class_data.instance_fields:
                field_id += field.field_idx_diff.value
                field_type = self.data.field_ids[field_id].type_name
                if field_type.endswith(';'):
                    field_type = field_type[1:-1]
                class_type = self.data.field_ids[field_id].class_name
                if class_type.endswith(';'):
                    class_type = class_type[1:-1]
                class_obj['fields'].append({'name': self.data.field_ids[field_id].field_name,
                                            'type': field_type, 'class': class_type,
                                            'field_type': 'instance'})
            metadata['classes'].append(class_obj)

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
