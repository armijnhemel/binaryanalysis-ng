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
import tlsh
from UnpackParser import WrappedUnpackParser
from bangandroid import unpack_dex

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import dex

class DexUnpackParser(WrappedUnpackParser):
#class DexUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'dex\n')
    ]
    pretty_name = 'dex'

    # There are many opcodes in Android, not all of which are in
    # every version of Android.

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_dex(fileresult, scan_environment, offset, unpack_dir)

    def parse_bytecode(self, bytecode):
        # parse enough of the bytecode to be able to extract the strings
        pass

    def parse(self):
        try:
            self.data = dex.Dex.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)

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
            class_obj['strings'] = []
            class_obj['methods'] = []

            # process direct methods
            method_id = 0
            for method in class_definition.class_data.direct_methods:
                if method.code is None:
                    continue

                # compute various hashes for the bytecode and store them
                hashes = {}
                sha256 = hashlib.sha256(method.code.insns.raw_bytecode).hexdigest()
                hashes['sha256'] = sha256
                tlsh_hash = tlsh.hash(method.code.insns.raw_bytecode)
                if tlsh_hash != 'TNULL':
                    hashes['tlsh'] = tlsh_hash
                else:
                    hashes['tlsh'] = None

                # extract the relevant strings from the bytecode and store them
                res = self.parse_bytecode(method.code.insns.raw_bytecode)

                method_id += method.method_idx_diff.value
                class_obj['methods'].append({'name': self.data.method_ids[method_id].method_name,
                                            'class_type': 'direct', 'bytecode_hashes': hashes})
            # process virtual methods
            method_id = 0
            for method in class_definition.class_data.virtual_methods:
                if method.code is None:
                    continue

                # compute various hashes for the bytecode and store them
                hashes = {}
                sha256 = hashlib.sha256(method.code.insns.raw_bytecode).hexdigest()
                hashes['sha256'] = sha256
                tlsh_hash = tlsh.hash(method.code.insns.raw_bytecode)
                if tlsh_hash != 'TNULL':
                    hashes['tlsh'] = tlsh_hash
                else:
                    hashes['tlsh'] = None

                # extract the relevant strings from the bytecode and store them
                method_id += method.method_idx_diff.value
                class_obj['methods'].append({'name': self.data.method_ids[method_id].method_name,
                                            'class_type': 'virtual', 'bytecode_hashes': hashes})

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
