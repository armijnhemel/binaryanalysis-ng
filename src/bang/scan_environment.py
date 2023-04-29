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

import multiprocessing
import pathlib

from dataclasses import dataclass
from typing import Any

import ahocorasick
from .log import log

class EmptyAutomaton:
    def iter(self, *args, **kwargs):
        return []

class BangConfig:
    def __init__(self):
        self._temporary_directory = pathlib.Path('')

    @property
    def temporary_directory(self):
        return self._temporary_directory

    @temporary_directory.setter
    def temporary_directory(self, temp_dir: pathlib.Path):
        self._temporary_directory = temp_dir


class ParserCollection:

    def __init__(self):
        self.clear()

    def clear(self):
        self._unpackparsers = {}
        self._unpackparsers_for_extensions = {}
        self._unpackparsers_for_signatures = {}
        self._unpackparsers_for_featureless_files = []
        self.longest_signature_length = 0

    def add(self, unpackparser):
        self._unpackparsers[unpackparser.pretty_name] = unpackparser
        for ext in unpackparser.extensions:
            self._unpackparsers_for_extensions.setdefault(ext,[]).append(unpackparser)
        for signature in unpackparser.signatures:
            self._unpackparsers_for_signatures.setdefault(signature,[]).append(unpackparser)
        if unpackparser.scan_if_featureless:
            self._unpackparsers_for_featureless_files.append(unpackparser)

    @property
    def unpackparsers(self):
        return self._unpackparsers.values()

    @unpackparsers.setter
    def unpackparsers(self, iterable):
        self.clear()
        for up in iterable:
            self.add(up)

    def get(self, key, default=None):
        return self._unpackparsers.get(key, default)

    @property
    def unpackparsers_for_extensions(self):
        return self._unpackparsers_for_extensions

    @property
    def unpackparsers_for_signatures(self):
        return self._unpackparsers_for_signatures

    @property
    def unpackparsers_for_featureless_files(self):
        return self._unpackparsers_for_featureless_files

    def build_automaton(self):
        if ahocorasick.unicode != 0:
            raise ImportError('ahocorasick module must be compiled in bytes mode')

        # initialize the automaton
        self._automaton = ahocorasick.Automaton()
        self.longest_signature_length = 0

        for u in self.unpackparsers:
            for s in u.signatures:
                log.debug(f'build_automaton: ({s},{u}, {s[0]+len(s[1])-1=}')

                # check if the key already exists: some parsers could
                # have the same signature. Normally add_word() would simply
                # overwrite the value, so first retrieve the old value
                if s[1] in self._automaton:
                    unpackers = self._automaton.pop(s[1])[1]
                    unpackers.append(u)
                    self._automaton.add_word(s[1], (s[0]+len(s[1])-1, unpackers))
                else:
                    self._automaton.add_word(s[1], (s[0]+len(s[1])-1, [u]))
                self.longest_signature_length = max(self.longest_signature_length, len(s[1]))

        if len(self._automaton) > 0:
            self._automaton.make_automaton()
        else:
            self._automaton = EmptyAutomaton()

    @property
    def automaton(self):
        return self._automaton

@dataclass
class ScanEnvironment:
    unpack_directory: pathlib.Path
    scan_queue: Any = None
    job_wait_time: int = 5
    signature_chunk_size: int = 1024
    parsers: ParserCollection = ParserCollection()
    configuration: BangConfig = BangConfig()
