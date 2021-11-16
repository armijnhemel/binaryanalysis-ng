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

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import android_resource


class AndroidResourceUnpackParser(UnpackParser):
    extensions = ['resources.arsc']
    signatures = [
        (0, b'\x03\x00\x08\x00')
    ]
    pretty_name = 'androidresource'

    def parse(self):
        try:
            self.data = android_resource.AndroidResource.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)
        if self.data.resource.header.type == android_resource.AndroidResource.ResourceTypes.xml:
            # walk to see if the XML is actually correct
            elem_count = 0
            namespace_count = 0
            check_condition(self.data.resource.body.body.nodes != [],
                            "no elements found")
            for node in self.data.resource.body.body.nodes:
                if node.header.type == android_resource.AndroidResource.ResourceTypes.xml_start_element:
                    elem_count += 1
                elif node.header.type == android_resource.AndroidResource.ResourceTypes.xml_end_element:
                    elem_count -= 1
                elif node.header.type == android_resource.AndroidResource.ResourceTypes.xml_start_namespace:
                    namespace_count += 1
                elif node.header.type == android_resource.AndroidResource.ResourceTypes.xml_end_namespace:
                    namespace_count -= 1
                check_condition(elem_count >= 0, "unbalanced XML elements")
                check_condition(namespace_count >= 0, "unbalanced XML namespace")

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['resource', 'android resource', 'android']
        metadata = {}

        if self.data.resource.header.type == android_resource.AndroidResource.ResourceTypes.xml:
            labels.append('binary xml')

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
