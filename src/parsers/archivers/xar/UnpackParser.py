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
import collections
import xml.dom
import defusedxml
from UnpackParser import WrappedUnpackParser
from bangunpack import unpack_xar

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationNotEqualError
from . import xar


#class XarUnpackParser(UnpackParser):
class XarUnpackParser(WrappedUnpackParser):
    extensions = []
    signatures = [
        (0, b'\x78\x61\x72\x21')
    ]
    pretty_name = 'xar'

    def unpack_function(self, fileresult, scan_environment, offset, unpack_dir):
        return unpack_xar(fileresult, scan_environment, offset, unpack_dir)

    def parse(self):
        try:
            self.data = xar.Xar.from_io(self.infile)
        except (Exception, ValidationNotEqualError) as e:
            raise UnpackParserException(e.args)
        check_condition(len(self.data._raw__raw_toc) == self.data.header.len_toc_compressed,
                        "invalid compressed TOC length")
        check_condition(len(self.data.toc.xml_string) == self.data.header.toc_length_uncompressed,
                        "invalid uncompressed TOC length")

        # parse the TOC
        try:
            tocdom = defusedxml.minidom.parseString(self.data.toc.xml_string)
        except Exception as e:
            raise UnpackParserException(e.args)

        # traverse the TOC for sanity checks
        check_condition(tocdom.documentElement.tagName == 'xar',
                        "invalid TOC, \"xar\" is not the top level element")

        # there should be one single node called "toc". If not, it
        # is a malformed XAR table of contents.
        havevalidtoc = False
        for i in tocdom.documentElement.childNodes:
            # the childnodes of the element could also
            # include text nodes, which are not interesting
            if i.nodeType == xml.dom.Node.ELEMENT_NODE:
                if i.tagName == 'toc':
                    havevalidtoc = True
                    tocnode = i
                    break

        check_condition(havevalidtoc, "invalid TOC, \"toc\" element not found")

        # Then further traverse the DOM for sanity checks.
        # The offsets are relative to the end of the header
        end_of_header = self.data._io.pos()
        self.unpacked_size = end_of_header

        # the XML consists of a top level checksum, followed by metadata
        # for each file in the archive, which can be nested. The metadata
        # for file includes offset and length for the file itself as well
        # as any extra metadata like resource forks or extended attributes.
        # This extra metadata is optional.

        nodes_to_traverse = collections.deque()
        for child_node in tocnode.childNodes:
            if child_node.nodeType == xml.dom.Node.ELEMENT_NODE:
                if child_node.tagName == 'checksum':
                    # top level checksum should have a size field and offset
                    for ic in child_node.childNodes:
                        if ic.nodeType == xml.dom.Node.ELEMENT_NODE:
                            if ic.tagName == 'offset':
                                # traverse the child nodes
                                for dd in ic.childNodes:
                                    if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                        try:
                                            checksum_offset = int(dd.data.strip())
                                        except ValueError as e:
                                            raise UnpackParserException(e.args)
                            elif ic.tagName == 'size':
                                # traverse the child nodes
                                for dd in ic.childNodes:
                                    if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                        try:
                                            checksum_size = int(dd.data.strip())
                                        except ValueError as e:
                                            raise UnpackParserException(e.args)
                    check_condition(end_of_header + checksum_offset + checksum_size <= self.fileresult.filesize,
                                    "checksum cannot be outside of file")
                    self.unpacked_size = max(self.unpacked_size, end_of_header + checksum_offset + checksum_size)
                elif child_node.tagName == 'file':
                    seen_type = False
                    seen_name = False
                    for ic in child_node.childNodes:
                        if ic.nodeType == xml.dom.Node.ELEMENT_NODE:
                            if ic.tagName in ['data', 'ea']:
                                for file_node in ic.childNodes:
                                    if file_node.nodeType == xml.dom.Node.ELEMENT_NODE:
                                        if file_node.tagName == 'offset':
                                            # traverse the child nodes
                                            for dd in file_node.childNodes:
                                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                                    try:
                                                        data_offset = int(dd.data.strip())
                                                    except ValueError as e:
                                                        raise UnpackParserException(e.args)
                                        elif file_node.tagName == 'length':
                                            # traverse the child nodes
                                            for dd in file_node.childNodes:
                                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                                    try:
                                                        data_length = int(dd.data.strip())
                                                    except ValueError as e:
                                                        raise UnpackParserException(e.args)
                                check_condition(end_of_header + data_offset + data_length <= self.fileresult.filesize,
                                    "file data cannot be outside of file")
                                self.unpacked_size = max(self.unpacked_size, end_of_header + data_offset + data_length)
                            else:
                                if ic.tagName == 'type':
                                    seen_type = True
                                elif ic.tagName == 'name':
                                    seen_name = True
                    check_condition(seen_type, "missing 'type' in TOC")

    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        """extract any files from the input file"""
        tocdom = defusedxml.minidom.parseString(self.data.toc.xml_string)
        for i in tocdom.documentElement.childNodes:
            # the childnodes of the element could also
            # include text nodes, which are not interesting
            if i.nodeType == xml.dom.Node.ELEMENT_NODE:
                if i.tagName == 'toc':
                    tocnode = i
                    break

        # process all the file and directory entries. These can
        # be nested (files in directories, subdirectories), which
        # is relevant for path information.
        nodes_to_traverse = collections.deque()
        for child_node in tocnode.childNodes:
            if child_node.nodeType == xml.dom.Node.ELEMENT_NODE:
                if child_node.tagName == 'file':
                    outlabels = []

                    # inspect the contents of the node. Since it is not
                    # guaranteed in which order the elements appear in the XML
                    # file some information has to be stored first.
                    nodename = None
                    nodetype = None
                    nodedata = None

                    for ic in child_node.childNodes:
                        if ic.nodeType == xml.dom.Node.ELEMENT_NODE:
                            if ic.tagName == 'name':
                                # grab the name of the entry and store it in
                                # nodename.
                                for cn in ic.childNodes:
                                    if cn.nodeType == xml.dom.Node.TEXT_NODE:
                                        nodename = cn.data.strip()
                                        # remove any superfluous / characters.
                                        # This should not happen with XAR but
                                        # just in case...
                                        while nodename.startswith('/'):
                                            nodename = nodename[1:]
                            elif ic.tagName == 'type':
                                # grab the type of the entry and store it in
                                # nodetype.
                                for cn in ic.childNodes:
                                    if cn.nodeType == xml.dom.Node.TEXT_NODE:
                                        nodetype = cn.data.strip()
                            elif ic.tagName == 'data':
                                for file_node in ic.childNodes:
                                    if file_node.nodeType == xml.dom.Node.ELEMENT_NODE:
                                        if file_node.tagName == 'offset':
                                            # traverse the child nodes
                                            for dd in file_node.childNodes:
                                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                                    try:
                                                        data_offset = int(dd.data.strip())
                                                    except ValueError as e:
                                                        raise UnpackParserException(e.args)
                                        elif file_node.tagName == 'length':
                                            # traverse the child nodes
                                            for dd in file_node.childNodes:
                                                if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                                    try:
                                                        data_length = int(dd.data.strip())
                                                    except ValueError as e:
                                                        raise UnpackParserException(e.args)
                    print(nodename)

        return []

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['archive', 'xar']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
