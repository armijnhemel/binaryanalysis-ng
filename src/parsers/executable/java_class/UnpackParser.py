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
import mutf8

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import java_class


class JavaClassUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\xca\xfe\xba\xbe')
    ]
    pretty_name = 'javaclass'

    def parse(self):
        try:
            self.data = java_class.JavaClass.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # make sure that all the pointers
        # into the constant pool are actually valid
        constant_pool_index = 1
        for i in self.data.constant_pool:
            if i.is_prev_two_entries:
                constant_pool_index += 1
                continue
            if self.data.this_class == constant_pool_index:
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    pass

            try:
                if type(i.cp_info) == java_class.JavaClass.StringCpInfo:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                pass
            except AttributeError as e:
                raise UnpackParserException(e.args)
            constant_pool_index += 1

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = [ 'java class' ]

        # store the results for Java:
        # * methods
        # * interfaces (TODO)
        # * fields
        # * source file name
        # * class name
        # * strings
        metadata = {}

        # walk the constant pool for information that isn't
        # available some other way.
        metadata['strings'] = []
        constant_pool_index = 1
        for i in self.data.constant_pool:
            if i.is_prev_two_entries:
                constant_pool_index += 1
                continue
            if self.data.this_class == constant_pool_index:
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
                    metadata['classname'] = decoded_string
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    pass
            if type(i.cp_info) == java_class.JavaClass.StringCpInfo:
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.cp_info.name_as_str)
                    metadata['strings'].append(decoded_string)
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    pass
            constant_pool_index += 1

        #metadata['interfaces'] = []
        #for i in self.data.interfaces:
        #    try:
        #        decoded_string = mutf8.decode_modified_utf8(i.name_as_str)
        #        metadata['interfaces'].append(decoded_string)
        #    except (UnicodeDecodeError, AttributeError):
        #        pass

        metadata['fields'] = []
        for i in self.data.fields:
            try:
                decoded_string = mutf8.decode_modified_utf8(i.name_as_str)
                metadata['fields'].append(decoded_string)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                pass

        metadata['methods'] = []
        for i in self.data.methods:
            try:
                decoded_string = mutf8.decode_modified_utf8(i.name_as_str)
                metadata['methods'].append(decoded_string)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                pass

        for i in self.data.attributes:
            try:
                name = mutf8.decode_modified_utf8(i.name_as_str)
            except UnicodeDecodeError:
                # This shouldn't happen and means there
                # is an error in the mutf8 package
                continue

            if name == 'SourceFile':
                try:
                    decoded_string = mutf8.decode_modified_utf8(i.info.sourcefile_as_str)
                    metadata['sourcefile'] = decoded_string
                except UnicodeDecodeError:
                    # This shouldn't happen and means there
                    # is an error in the mutf8 package
                    continue
        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
