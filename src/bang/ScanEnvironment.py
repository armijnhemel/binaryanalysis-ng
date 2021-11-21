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
# Copyright 2018-2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import os
import multiprocessing
import ahocorasick
import pathlib
from dataclasses import dataclass
from typing import Any
from ByteCountReporter import *
from PickleReporter import *
from JsonReporter import *
from .log import log

class EmptyAutomaton:
    def iter(self, *args, **kwargs):
        return []

class ParserCollection:

    def __init__(self):
        self.clear()

    def clear(self):
        self._unpackparsers = []
        self._unpackparsers_for_extensions = {}
        self._unpackparsers_for_signatures = {}
        self._unpackparsers_for_featureless_files = []
        self.longest_signature_length = 0

    def add(self, unpackparser):
        self._unpackparsers.append(unpackparser)
        for ext in unpackparser.extensions:
            self._unpackparsers_for_extensions.setdefault(ext,[]).append(unpackparser)
        for signature in unpackparser.signatures:
            self._unpackparsers_for_signatures.setdefault(signature,[]).append(unpackparser)
        if unpackparser.scan_if_featureless:
            self._unpackparsers_for_featureless_files.append(unpackparser)

    @property
    def unpackparsers(self):
        return self._unpackparsers

    @unpackparsers.setter
    def unpackparsers(self, iterable):
        self.clear()
        for up in iterable:
            self.add(up)

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
        self._automaton = ahocorasick.Automaton()
        self.longest_signature_length = 0
        for u in self.unpackparsers:
            for s in u.signatures:
                log.debug(f'build_automaton: ({s},{u}, {s[0]+len(s[1])-1=}')
                self._automaton.add_word(s[1], (s[0]+len(s[1])-1, u))
                self.longest_signature_length = max(self.longest_signature_length, len(s))
        if len(self._automaton) > 0:
            self._automaton.make_automaton()
        else:
            self._automaton = EmptyAutomaton()

    @property
    def automaton(self):
        return self._automaton

@dataclass
class ScanEnvironment:
    maxbytes: int
    readsize: int
    createbytecounter: bool
    createjson: bool
    tlshmaximum: int
    unpackdirectory: pathlib.Path
    temporarydirectory: pathlib.Path
    job_wait_time: int = 10
    scan_queue: Any = None
    parsers: ParserCollection = ParserCollection()
    # resultqueue:bool
    # processlock:bool
    # checksumdict:bool
    signature_chunk_size: int = 1024

