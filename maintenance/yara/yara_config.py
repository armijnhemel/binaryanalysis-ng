#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
Helper classes for parsing YARA configuration
'''

import multiprocessing
import pathlib
import tempfile

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class YaraConfigException(Exception):
    '''Generic exception for parsing YARA configuration files'''
    pass


class YaraConfig:
    def __init__(self, config_file):
        # read the configuration file. This is in YAML format
        try:
            self.config = load(config_file, Loader=Loader)
        except (YAMLError, PermissionError) as e:
            raise YaraConfigException(e.args)

    def parse(self):
        yara_env = {}
        heuristics = {}

        # general sanity checks to see if the required sections are present
        for i in ['general', 'yara']:
            if i not in self.config:
                raise YaraConfigException("Section %s missing in configuration file" % i)

        # sanity checks for yara_directory
        if 'yara_directory' not in self.config['yara']:
            raise YaraConfigException("'yara_directory' not defined in configuration")

        yara_directory = pathlib.Path(self.config['yara']['yara_directory'])
        if not yara_directory.exists():
            raise YaraConfigException("yara_directory does not exist")

        if not yara_directory.is_dir():
            raise YaraConfigException("'yara_directory' is not a valid directory")

        # check if the yara directory is writable
        try:
            temp_name = tempfile.NamedTemporaryFile(dir=yara_directory)
            temp_name.close()
        except:
            raise YaraConfigException("'yara_directory' cannot be written to")

        temporary_directory = None

        verbose = False
        if 'verbose' in self.config['general']:
            if isinstance(self.config['general']['verbose'], bool):
                verbose = self.config['general']['verbose']

        error_fatal = True
        if 'error_fatal' in self.config['general']:
            if isinstance(self.config['general']['error_fatal'], bool):
                error_fatal = self.config['general']['error_fatal']

        # directory for unpacking. By default this will be /tmp or whatever
        # the system default is.
        temporary_directory = None

        if 'tempdir' in self.config['general']:
            temporary_directory = pathlib.Path(self.config['general']['tempdir'])
            if temporary_directory.exists():
                if temporary_directory.is_dir():
                    # check if the temporary directory is writable
                    try:
                        temp_name = tempfile.NamedTemporaryFile(dir=temporary_directory)
                        temp_name.close()
                    except:
                        temporary_directory = None
                else:
                    temporary_directory = None
            else:
                temporary_directory = None

        # set the number of threads that should be used
        threads = multiprocessing.cpu_count()
        if 'threads' in self.config['general']:
            if isinstance(self.config['general']['threads'], int):
                threads = self.config['general']['threads']

        # option to tell whether or not identifiers matched by YARA
        # should be delimited or can be a substring.
        fullword = True
        if 'fullword' in self.config['yara']:
            if isinstance(self.config['yara']['fullword'], bool):
                fullword = self.config['yara']['fullword']

        json_directory = yara_directory
        if 'json_directory' in self.config['yara']:
            json_directory = pathlib.Path(self.config['yara']['json_directory'])
            if json_directory != yara_directory:
                if not json_directory.exists():
                    raise YaraConfigException("'json_directory' does not exist")
                if not json_directory.is_dir():
                    raise YaraConfigException("'json_directory' is not a valid directory")
                # check if the json directory is writable
                try:
                    temp_name = tempfile.NamedTemporaryFile(dir=json_directory)
                    temp_name.close()
                except:
                    raise YaraConfigException("'json_directory' cannot be written to")

        operator = 'and'
        if 'operator' in self.config['yara']:
            if self.config['yara']['operator'] in ['and', 'or']:
                operator = self.config['yara']['operator']

        # heuristics used for generating YARA rules
        string_min_cutoff = 8
        if 'string_min_cutoff' in self.config['yara']:
            if isinstance(self.config['yara']['string_min_cutoff'], int):
                string_min_cutoff = self.config['yara']['string_min_cutoff']

        string_max_cutoff = 200
        if 'string_max_cutoff' in self.config['yara']:
            if isinstance(self.config['yara']['string_max_cutoff'], int):
                string_max_cutoff = self.config['yara']['string_max_cutoff']

        identifier_cutoff = 2
        if 'identifier_cutoff' in self.config['yara']:
            if isinstance(self.config['yara']['identifier_cutoff'], int):
                identifier_cutoff = self.config['yara']['identifier_cutoff']

        max_identifiers = 10000
        if 'max_identifiers' in self.config['yara']:
            if isinstance(self.config['yara']['max_identifiers'], int):
                max_identifiers = self.config['yara']['max_identifiers']

        strings_percentage = 10
        if 'strings_percentage' in self.config['yara']:
            if isinstance(self.config['yara']['strings_percentage'], int):
                strings_percentage = self.config['yara']['strings_percentage']
        heuristics['strings_percentage'] = strings_percentage

        functions_percentage = 10
        if 'functions_percentage' in self.config['yara']:
            if isinstance(self.config['yara']['functions_percentage'], int):
                functions_percentage = self.config['yara']['functions_percentage']
        heuristics['functions_percentage'] = functions_percentage

        variables_percentage = 10
        if 'variables_percentage' in self.config['yara']:
            if isinstance(self.config['yara']['variables_percentage'], int):
                variables_percentage = self.config['yara']['variables_percentage']
        heuristics['variables_percentage'] = variables_percentage

        strings_matched = 1
        if 'strings_matched' in self.config['yara']:
            if isinstance(self.config['yara']['strings_matched'], int):
                strings_matched = self.config['yara']['strings_matched']
        heuristics['strings_matched'] = strings_matched

        functions_matched = 1
        if 'functions_matched' in self.config['yara']:
            if isinstance(self.config['yara']['functions_matched'], int):
                functions_matched = self.config['yara']['functions_matched']
        heuristics['functions_matched'] = functions_matched

        variables_matched = 1
        if 'variables_matched' in self.config['yara']:
            if isinstance(self.config['yara']['variables_matched'], int):
                variables_matched = self.config['yara']['variables_matched']
        heuristics['variables_matched'] = variables_matched

        strings_minimum_present = 10
        if 'strings_minimum_present' in self.config['yara']:
            if isinstance(self.config['yara']['strings_minimum_present'], int):
                strings_minimum_present = self.config['yara']['strings_minimum_present']
        heuristics['strings_minimum_present'] = strings_minimum_present

        functions_minimum_present = 10
        if 'functions_minimum_present' in self.config['yara']:
            if isinstance(self.config['yara']['functions_minimum_present'], int):
                functions_minimum_present = self.config['yara']['functions_minimum_present']
        heuristics['functions_minimum_present'] = functions_minimum_present

        variables_minimum_present = 10
        if 'variables_minimum_present' in self.config['yara']:
            if isinstance(self.config['yara']['variables_minimum_present'], int):
                variables_minimum_present = self.config['yara']['variables_minimum_present']
        heuristics['variables_minimum_present'] = variables_minimum_present

        strings_extracted = 5
        if 'strings_extracted' in self.config['yara']:
            if isinstance(self.config['yara']['strings_extracted'], int):
                strings_extracted = self.config['yara']['strings_extracted']
        heuristics['strings_extracted'] = strings_extracted

        functions_extracted = 5
        if 'functions_extracted' in self.config['yara']:
            if isinstance(self.config['yara']['functions_extracted'], int):
                functions_extracted = self.config['yara']['functions_extracted']
        heuristics['functions_extracted'] = functions_extracted

        variables_extracted = 5
        if 'variables_extracted' in self.config['yara']:
            if isinstance(self.config['yara']['variables_extracted'], int):
                variables_extracted = self.config['yara']['variables_extracted']
        heuristics['variables_extracted'] = variables_extracted

        # option to tell whether or not to ignore weak ELF symbols
        ignore_weak_symbols = False
        if 'ignore_weak_symbols' in self.config['yara']:
            if isinstance(self.config['yara']['ignore_weak_symbols'], bool):
                ignore_weak_symbols = self.config['yara']['ignore_weak_symbols']

        ignore_ocaml = False
        if 'ignore_ocaml' in self.config['yara']:
            if isinstance(self.config['yara']['ignore_ocaml'], bool):
                ignore_ocaml = self.config['yara']['ignore_ocaml']

        yara_env = {'verbose': verbose, 'error_fatal': error_fatal,
                    'string_min_cutoff': string_min_cutoff,
                    'string_max_cutoff': string_max_cutoff,
                    'identifier_cutoff': identifier_cutoff,
                    'max_identifiers': max_identifiers,
                    'ignore_weak_symbols': ignore_weak_symbols,
                    'ignore_ocaml': ignore_ocaml,
                    'fullword': fullword, 'threads': threads,
                    'yara_directory': yara_directory, 'heuristics': heuristics,
                    'temporary_directory': temporary_directory,
                    'json_directory': json_directory,
                    'operator': operator}
        return yara_env
