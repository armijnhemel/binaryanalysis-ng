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
# Copyright 2018-2019 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import pathlib

class FileResult:
    """stores all the information about the file that has been discovered
    so far.
    """
    def __init__(self, parent, rel_filename, labels):
        """Constructor.
        parent: parent fileresult, None if file is the top file to unpack.
        rel_filename: path relative to the unpack directory root, unless
        labels: labels associated with the file.
        """
        self.hash = {}
        self.filename = rel_filename
        # TODO: self.parent must be the fileresult
        if parent:
            self.parent = parent.filename
            self.parentlabels = parent.labels
        else:
            self.parent = None
            self.parentlabels = set()
        self.labels = labels
        self.unpackedfiles = None
        self.metadata = None
        self.filesize = None
        self.mimetype = None
        self.mimetype_encoding = None

    def set_filesize(self, size):
        self.filesize = size

    def has_parent(self):
        return self.parent is not None

    def get_hashresult(self):
        return self.hash

    def set_hashresult(self, hashtype, value):
        self.hash[hashtype] = value

    def init_unpacked_files(self):
        self.unpackedfiles = []

    def add_unpackedfile(self, report):
        self.unpackedfiles.append(report)

    def set_mimetype(self, mimeres):
        self.mimetype = mimeres[0]
        self.mimetype_encoding = mimeres[1]

    def set_metadata(self, metadata):
        self.metadata = metadata

    def get(self):
        """gets the fileresult as a dictionary."""
        d = {
            'hash': self.hash,
            'labels': list(self.labels),
            'filename': str(self.filename),
        }
        if self.filesize is not None:
            d['filesize'] = self.filesize
        if self.unpackedfiles is not None:
            d['unpackedfiles'] = self.unpackedfiles
        if self.has_parent():
            d['parent'] = str(self.parent)
        if self.mimetype is not None:
            d['mimetype'] = self.mimetype
            if self.mimetype_encoding is not None:
                d['mimetype encoding'] = self.mimetype_encoding
        return d

    def get_hash(self, algorithm='sha256'):
        return self.hash[algorithm]

    def get_unpack_directory_parent(self):
        if self.parent is None:
            return pathlib.Path(pathlib.Path(self.filename).name)
        return pathlib.Path(self.filename)
