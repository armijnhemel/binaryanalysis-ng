#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Copyright Armijn Hemel
# SPDX-License-Identifier: GPL-3.0-only

import importlib
import inspect
import os
import pathlib
import pkgutil

from . import parsers
from . import reporters
from .UnpackParser import UnpackParser
from .Reporter import Reporter


def _get_unpackers_recursive(unpackers_root, parent_module_path):
    abs_module_path = unpackers_root / parent_module_path
    for m in pkgutil.iter_modules([str(abs_module_path)]):
        full_module_path = parent_module_path / m.name
        if (unpackers_root / full_module_path).is_dir():
            try:
                full_module_name = '.'.join(full_module_path.parts)
                module_name = f'.{full_module_name}.UnpackParser'
                module = importlib.import_module(module_name, package='bang.parsers')
                for name, member in inspect.getmembers(module):
                    if inspect.isclass(member) and issubclass(member, UnpackParser) \
                        and member != UnpackParser:
                        # unpackers.append(member)
                        yield member
            except ModuleNotFoundError as e:
                pass
            yield from _get_unpackers_recursive(unpackers_root, full_module_path )

def get_unpackers():
    unpackers = _get_unpackers_recursive(
            pathlib.Path(os.path.dirname(parsers.__file__)), pathlib.Path('.'))
    return list(unpackers)

def _get_reporters_recursive(reporters_root, parent_module_path):
    abs_module_path = reporters_root / parent_module_path
    for m in pkgutil.iter_modules([str(abs_module_path)]):
        full_module_path = parent_module_path / m.name
        if (reporters_root / full_module_path).is_dir():
            try:
                full_module_name = '.'.join(full_module_path.parts)
                module_name = f'.{full_module_name}.Reporter'
                module = importlib.import_module(module_name, package='bang.reporters')
                for name, member in inspect.getmembers(module):
                    if inspect.isclass(member) and issubclass(member, Reporter) \
                        and member != Reporter:
                        # unpackers.append(member)
                        yield member
            except ModuleNotFoundError as e:
                pass
            yield from _get_reporters_recursive(reporters_root, full_module_path )

def get_reporters():
    reporters_list = _get_reporters_recursive(
            pathlib.Path(os.path.dirname(reporters.__file__)), pathlib.Path('.'))
    return list(reporters_list)
