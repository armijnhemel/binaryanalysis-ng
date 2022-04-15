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

# Derived from specifications at:
# https://github.com/mackyle/xar/wiki/xarformat
#
# Basically XAR is a header, a zlib compressed XML file describing
# where to find files and how they were compressed, and then the
# actual data (perhaps compressed).
#
# Compression depends on the options provided and the version of XAR being
# used. Fedora's standard version uses:
#
# * none
# * gzip (default, but it is actually zlib's DEFLATE)
# * bzip2
#
# Other versions (from Git) can also use:
# * xz
# * lzma

import bz2
import collections
import hashlib
import lzma
import os
import pathlib
import xml.dom
import zlib

import defusedxml

from FileResult import FileResult

from UnpackParser import UnpackParser, check_condition
from UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import xar


class XarUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x78\x61\x72\x21')
    ]
    pretty_name = 'xar'

    def parse(self):
        try:
            self.data = xar.Xar.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
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
        have_valid_toc = False
        for i in tocdom.documentElement.childNodes:
            # the childnodes of the element could also
            # include text nodes, which are not interesting
            if i.nodeType == xml.dom.Node.ELEMENT_NODE:
                if i.tagName == 'toc':
                    have_valid_toc = True
                    tocnode = i
                    break

        check_condition(have_valid_toc, "invalid TOC, \"toc\" element not found")

        # Then further traverse the DOM for sanity checks.
        # The offsets are relative to the end of the header
        self.end_of_header = self.data._io.pos()
        self.unpacked_size = self.end_of_header

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
                    check_condition(self.end_of_header + checksum_offset + checksum_size <= self.fileresult.filesize,
                                    "checksum cannot be outside of file")
                    self.unpacked_size = max(self.unpacked_size, self.end_of_header + checksum_offset + checksum_size)
                else:
                    nodes_to_traverse.append((child_node, pathlib.Path('')))

        self.nodes = []
        file_ids = set()
        self.file_id_to_path = {}

        # now keep processing files, until none
        # are left to process.
        while True:
            try:
                (node, curcwd) = nodes_to_traverse.popleft()
            except:
                break

            if node.tagName == 'file':
                seen_type = False
                seen_name = False

                node_name = None
                node_type = None
                compression = 'gzip'

                extracted_checksum = None
                archived_checksum = None
                extracted_checksum_type = None
                archived_checksum_type = None

                file_id = node.getAttribute('id')
                check_condition(file_id != '', "invalid file id")

                file_ids.add(file_id)

                # for symbolic links
                link_target = None

                # for hardlinks
                type_of_link = ''

                file_nodes = []

                for ic in node.childNodes:
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
                                    elif file_node.tagName == 'encoding':
                                        compression_string = file_node.getAttribute('style')
                                        if 'gzip' in compression_string:
                                            compression = 'gzip'
                                        elif 'bzip2' in compression_string:
                                            compression = 'bzip2'
                                        elif 'lzma' in compression_string:
                                            compression = 'lzma'
                                        elif 'xz' in compression_string:
                                            compression = 'xz'
                                        elif 'application/octet-stream' in compression_string:
                                            compression = 'none'
                                    elif file_node.tagName == 'extracted-checksum':
                                        extracted_checksum_style = file_node.getAttribute('style').lower()
                                        # verify if it is a valid hash
                                        check_condition(extracted_checksum_style in hashlib.algorithms_available,
                                                        "unsupported extracted checksum hash")

                                        for dd in file_node.childNodes:
                                            if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                                extracted_checksum = dd.data.strip()
                                    elif file_node.tagName == 'archived-checksum':
                                        archived_checksum_style = file_node.getAttribute('style').lower()
                                        check_condition(archived_checksum_style in hashlib.algorithms_available,
                                                        "unsupported extracted checksum hash")
                                        for dd in file_node.childNodes:
                                            if dd.nodeType == xml.dom.Node.TEXT_NODE:
                                                archived_checksum = dd.data.strip()
                            check_condition(self.end_of_header + data_offset + data_length <= self.fileresult.filesize,
                                "file data cannot be outside of file")
                            self.unpacked_size = max(self.unpacked_size, self.end_of_header + data_offset + data_length)
                        elif ic.tagName == 'type':
                            seen_type = True
                            for child_node in ic.childNodes:
                                if child_node.nodeType == xml.dom.Node.TEXT_NODE:
                                    node_type = child_node.data.strip()
                                    break
                            type_of_link = ic.getAttribute('link')
                        elif ic.tagName == 'name':
                            seen_name = True
                            for child_node in ic.childNodes:
                                if child_node.nodeType == xml.dom.Node.TEXT_NODE:
                                    node_name = child_node.data.strip()
                                    break
                        elif ic.tagName == 'file':
                            file_nodes.append(ic)
                        elif ic.tagName == 'link':
                            for child_node in ic.childNodes:
                                if child_node.nodeType == xml.dom.Node.TEXT_NODE:
                                    link_target = child_node.data.strip()
                                    break
                            check_condition(link_target != '', "invalid symbolic link target")

                check_condition(seen_type, "missing 'type' in TOC")
                check_condition(seen_name, "missing 'name' in TOC")

                full_node_name = curcwd / node_name
                self.file_id_to_path[file_id] = full_node_name

                if node_type == 'directory':
                    self.nodes.append({'name': full_node_name,
                                       'type': 'directory', 'id': file_id})
                    for n in file_nodes:
                        nodes_to_traverse.append((n, full_node_name))
                elif node_type == 'file':
                    self.nodes.append({'name': full_node_name, 'type': 'file',
                                       'id': file_id, 'compression': compression,
                                       'offset': data_offset, 'length': data_length,
                                       'archived_checksum': archived_checksum,
                                       'archived_checksum_style': archived_checksum_style,
                                       'extracted_checksum': extracted_checksum,
                                       'extracted_checksum_style': extracted_checksum_style})
                elif node_type == 'symlink':
                    self.nodes.append({'name': full_node_name,
                                       'type': 'symlink', 'id': file_id,
                                       'target': link_target})
                elif node_type == 'hardlink':
                    if type_of_link != 'original':
                        self.nodes.append({'name': full_node_name,
                                           'type': 'hardlink', 'id': file_id,
                                           'link_type': type_of_link})
                    else:
                        self.nodes.append({'name': full_node_name, 'type': 'file',
                                           'id': file_id, 'compression': compression,
                                           'offset': data_offset, 'length': data_length,
                                           'archived_checksum': archived_checksum,
                                           'archived_checksum_style': archived_checksum_style,
                                           'extracted_checksum': extracted_checksum,
                                           'extracted_checksum_style': extracted_checksum_style})
                elif node_type == 'fifo':
                    self.nodes.append({'name': full_node_name,
                                       'type': 'fifo', 'id': file_id})

        # sanity check the data and the checksums
        maxbytestoread = 10000000
        for node in self.nodes:
            if node['type'] == 'directory':
                continue

            if node['type'] == 'symlink':
                continue

            if node['type'] == 'hardlink':
                # extra sanity check
                check_condition(node['link_type'] in file_ids,
                                "invalid hardlink target")

            if node['type'] != 'file':
                continue

            self.infile.seek(self.end_of_header + node['offset'])
            extracted_hash = hashlib.new(node['extracted_checksum_style'])
            bytesread = 0

            if node['compression'] == 'none':
                # read in chunks of 10 MB
                while bytesread != node['length']:
                    buf = self.infile.read(min(maxbytestoread, node['length']-bytesread))
                    bytesread += len(buf)
                    extracted_hash.update(buf)
            else:
                if node['compression'] == 'bzip2':
                    decompressor = bz2.BZ2Decompressor()
                elif node['compression'] == 'gzip':
                    decompressor = zlib.decompressobj()
                elif node['compression'] == 'lzma':
                    decompressor = lzma.LZMADecompressor()
                elif node['compression'] == 'xz':
                    decompressor = lzma.LZMADecompressor()
                else:
                    raise UnpackParserException("compression not supported")

                # read in chunks of 10 MB
                while bytesread != node['length']:
                    buf = self.infile.read(min(maxbytestoread, node['length']-bytesread))

                    # decompress the data and check the hash
                    try:
                        decompressed_bytes = decompressor.decompress(buf)
                    except:
                        raise UnpackParserException("broken compressed data")
                    bytesread += len(buf)
                    extracted_hash.update(decompressed_bytes)

                    # there shouldn't be any unused data
                    if decompressor.unused_data != b'':
                        raise UnpackParserException("extra unused data")
            check_condition(extracted_hash.hexdigest() == node['extracted_checksum'],
                            "extracted-checksum mismatch")


    # make sure that self.unpacked_size is not overwritten
    def calculate_unpacked_size(self):
        pass

    def unpack(self):
        """extract any files from the input file"""
        unpacked_files = []

        maxbytestoread = 10000000
        for node in self.nodes:
            out_labels = []
            file_path = node['name']
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)

            if node['type'] == 'directory':
                out_labels = ['directory']
                os.makedirs(outfile_full, exist_ok=True)
            elif node['type'] == 'symlink':
                out_labels = ['symlink']
                outfile_full.symlink_to(node['target'])
            elif node['type'] == 'fifo':
                out_labels = ['fifo']
                os.mkfifo(outfile_full)
            else:
                if node['type'] != 'file':
                    continue
                self.infile.seek(self.end_of_header + node['offset'])
                bytesread = 0

                outfile = open(outfile_full, 'wb')
                if node['compression'] == 'none':
                    # read in chunks of 10 MB
                    while bytesread != node['length']:
                        buf = self.infile.read(min(maxbytestoread, node['length']-bytesread))
                        bytesread += len(buf)
                        outfile.write(buf)
                else:
                    if node['compression'] == 'bzip2':
                        decompressor = bz2.BZ2Decompressor()
                    elif node['compression'] == 'gzip':
                        decompressor = zlib.decompressobj()
                    elif node['compression'] == 'lzma':
                        decompressor = lzma.LZMADecompressor()
                    elif node['compression'] == 'xz':
                        decompressor = lzma.LZMADecompressor()

                    # read in chunks of 10 MB
                    while bytesread != node['length']:
                        buf = self.infile.read(min(maxbytestoread, node['length']-bytesread))

                        # decompress the data and write it to a file
                        decompressed_bytes = decompressor.decompress(buf)
                        outfile.write(decompressed_bytes)
                        bytesread += len(buf)
                outfile.close()

            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)

        # now process hardlinks
        for node in self.nodes:
            if node['type'] != 'hardlink':
                continue
            out_labels = ['hardlink']
            file_path = node['name']
            outfile_rel = self.rel_unpack_dir / file_path
            outfile_full = self.scan_environment.unpack_path(outfile_rel)
            os.makedirs(outfile_full.parent, exist_ok=True)

            target_rel = self.rel_unpack_dir / self.file_id_to_path[node['link_type']]
            target_full = self.scan_environment.unpack_path(target_rel)
            target_full.link_to(outfile_full)
            fr = FileResult(self.fileresult, self.rel_unpack_dir / file_path, set(out_labels))
            unpacked_files.append(fr)
        return unpacked_files

    def set_metadata_and_labels(self):
        """sets metadata and labels for the unpackresults"""
        labels = ['archive', 'xar']
        metadata = {}

        self.unpack_results.set_metadata(metadata)
        self.unpack_results.set_labels(labels)
