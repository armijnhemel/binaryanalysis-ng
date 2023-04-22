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
# Copyright - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import hashlib
import io
import pathlib

import xxhash
import zstandard

from bang.UnpackParser import UnpackParser, check_condition
from bang.UnpackParserException import UnpackParserException
from kaitaistruct import ValidationFailedError
from . import stone


class StoneUnpackParser(UnpackParser):
    extensions = []
    signatures = [
        (0, b'\x00mos')
    ]
    pretty_name = 'stone'

    def parse(self):
        try:
            self.data = stone.Stone.from_io(self.infile)
        except (Exception, ValidationFailedError) as e:
            raise UnpackParserException(e.args)

        # store the types of the sections for sanity checks
        sections = []

        for payload in self.data.payloads:
            check_condition(xxhash.xxh3_64(payload.data).digest() == payload.xxhash3_64,
                            "hash mismatch")
            sections.append(payload.type)

        # quick sanity check to see for the binary packages all the
        # sections are there before decompressing and storing the data
        # in memory.
        if self.data.header.type == stone.Stone.FileTypes.binary:
            check_condition(stone.Stone.PayloadType.meta in sections,
                            "mandatory meta section not found")
            check_condition(stone.Stone.PayloadType.layout in sections,
                            "mandatory layout section not found")
            check_condition(stone.Stone.PayloadType.index in sections,
                            "mandatory index section not found")
            check_condition(stone.Stone.PayloadType.content in sections,
                            "mandatory content section not found")

        # sanity checks: see if the contents of the payloads
        # can be decompressed by zstd if compressed
        for payload in self.data.payloads:
            if payload.compression == stone.Stone.Compression.no_compression:
                #check_condition(payload.len_usable_data == payload.len_data),
                #                "length mismatch")
                continue

            try:
                reader = zstandard.ZstdDecompressor().stream_reader(payload.data)
                unpacked_payload = reader.read()
            except Exception as e:
                raise UnpackParserException(e.args)

            check_condition(payload.len_usable_data == len(unpacked_payload),
                            "length mismatch")

            # extra sanity checks for packages
            if self.data.header.type == stone.Stone.FileTypes.binary:
                if payload.type == stone.Stone.PayloadType.meta:
                    try:
                        self.meta = stone.Stone.MetaRecords.from_bytes(unpacked_payload)
                    except (Exception, ValidationFailedError) as e:
                        raise UnpackParserException(e.args)
                elif payload.type == stone.Stone.PayloadType.layout:
                    try:
                        self.layout = stone.Stone.LayoutEntries.from_bytes(unpacked_payload)
                    except (Exception, ValidationFailedError) as e:
                        raise UnpackParserException(e.args)
                elif payload.type == stone.Stone.PayloadType.index:
                    try:
                        self.index = stone.Stone.IndexEntries.from_bytes(unpacked_payload)
                    except (Exception, ValidationFailedError) as e:
                        raise UnpackParserException(e.args)
                elif payload.type == stone.Stone.PayloadType.content:
                    self.content = unpacked_payload

            if self.data.header.type == stone.Stone.FileTypes.repository:
                if payload.type == stone.Stone.PayloadType.meta:
                    try:
                        self.meta = stone.Stone.MetaRecords.from_bytes(unpacked_payload)
                    except (Exception, ValidationFailedError) as e:
                        raise UnpackParserException(e.args)

        if self.data.header.type == stone.Stone.FileTypes.binary:
            # combine layout and index. Index contains the
            # offsets and sizes of the data, layout contains
            # names. These are linked by a hash value.
            self.hashes_to_data = {}
            self.symlinks = []
            self.directories = []
            content_length = len(self.content)

            for l in self.index.entries:
                if not l.hash_digest in self.hashes_to_data:
                    self.hashes_to_data[l.hash_digest] = {'offset': l.ofs_start, 'length': l.len_file}
                    check_condition(l.ofs_end <= content_length, "offset outside of file")

            for l in self.layout.entries:
                if l.file_type == stone.Stone.LayoutEntry.FileType.regular:
                    check_condition(l.source in self.hashes_to_data,
                                    "layout entry without corresponding index entry")
                    self.hashes_to_data[l.source]['name'] = l.target
                elif l.file_type == stone.Stone.LayoutEntry.FileType.symlink:
                    try:
                        src = l.source.rsplit(b'\x00')[0].decode()
                    except UnicodeDecodeError as e:
                        raise UnpackParserException(e.args)
                    self.symlinks.append({'source': pathlib.Path(src), 'target': pathlib.Path(l.target)})
                elif l.file_type == stone.Stone.LayoutEntry.FileType.directory:
                    self.directories.append(l.target)

    def unpack(self, meta_directory):
        if self.data.header.type == stone.Stone.FileTypes.binary:
            content_io = io.BytesIO(self.content)

            # first create the directories
            for d in self.directories:
                file_path = pathlib.Path(d)
                meta_directory.unpack_directory(file_path)

            # then write the individual files
            for d in self.hashes_to_data:
                file_path = pathlib.Path(self.hashes_to_data[d]['name'])

                with meta_directory.unpack_regular_file(file_path) as (unpacked_md, outfile):
                    content_io.seek(self.hashes_to_data[d]['offset'])
                    outfile.write(content_io.read(self.hashes_to_data[d]['length']))
                    yield unpacked_md

            # then create symbolic links
            for d in self.symlinks:
                meta_directory.unpack_symlink(d['target'], d['source'])

    labels = ['stone']

    @property
    def metadata(self):
        metadata = {}
        if self.data.header.type == stone.Stone.FileTypes.binary:
            metadata['type'] = 'binary'
        elif self.data.header.type == stone.Stone.FileTypes.repository:
            metadata['type'] = 'repository'
        return metadata
