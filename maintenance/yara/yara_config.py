#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

import sys
import os
import argparse
import pathlib
import multiprocessing

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

class ObjectDict(dict):
    def __setattr__(self, name, value):
        self[name] = value

    def __getattr__(self, name):
        return self[name]


class YaraBangConfigOptions():
    def __init__(self):
        self._set_default_options()
        self._parse_arguments()
        self._read_configuration_file()
        self._set_options_from_configuration_file()
        self._set_options_from_arguments()
        self._validate_options()

    def get(self):
        return self.options

    def _error(self, msg):
        print(msg, file=sys.stderr)
        sys.exit(1)

    def _set_default_options(self):
        self.defaults = {
            'cfg': None,
            'yara_directory': '',
            'temporarydirectory': None,
            'bangthreads': multiprocessing.cpu_count(),
            'string_cutoff': 8,
            'identifier_cutoff': 2,
            'verbose': False,
            'identifiers': [],
        }
        self.options = ObjectDict(dict(self.defaults))

    def _parse_arguments(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-c", "--config",
                                 action="store", dest="cfg",
                                 help="path to configuration file", metavar="FILE")
        self.parser.add_argument("-y", "--yara-directory",
                                 action="store", dest="yara_directory",
                                 help="path to YARA directory containing var/func files",
                                 metavar="DIR")
        self.parser.add_argument("-i", "--identifiers",
                                 action="store", dest="identifiers",
                                 help="path to pickle with low quality identifiers",
                                 metavar="FILE")
        self.args = self.parser.parse_args()
        self._check_configuration_file()

    def _check_configuration_file(self):
        if self.args.cfg is None:
            self.parser.error("No configuration file provided, exiting")

        config_file = pathlib.Path(self.args.cfg)
        # the configuration file should exist ...
        if not config_file.exists():
            self.parser.error("File %s does not exist, exiting." %
                                config_file)
        # ... and should be a real file
        if not config_file.is_file():
            self.parser.error("%s is not a regular file, exiting." %
                                config_file)

    def _read_configuration_file(self):
        # read the configuration file. This is in YAML format.
        environ = os.environ
        try:
            del environ['SHELL']
        except KeyError:
            pass
        try:
            configfile = open(self.args.cfg, 'r')
            self.config = load(configfile, Loader=Loader)
        except (YAMLError, PermissionError):
            self._error("Cannot open configuration file, exiting")

    def _set_string_option_from_config(self, option_name, section=None,
            option=None):
        if option is None:
            option = option_name
        try:
            v = self.config[section][option]
        except KeyError:
            return
        self.options[option_name] = v

    def _set_integer_option_from_config(self, option_name, section=None,
            option=None):
        if option is None:
            option = option_name
        try:
            v = int(self.config[section][option])
        except KeyError:
            return
        except ValueError:
            return
        self.options[option_name] = v

    def _set_boolean_option_from_config(self, option_name, section=None,
            option=None):
        if option is None:
            option = option_name
        try:
            v = self.config[section][option] == 'yes'
        except KeyError:
            return
        except ValueError:
            return
        self.options[option_name] = v

    def _set_options_from_configuration_file(self):
        # general settings
        self._set_integer_option_from_config('bangthreads',
                section='general', option='threads')
        self._set_boolean_option_from_config('verbose',
                section='general')

        # yara settings
        self._set_string_option_from_config('yara_directory',
                section='yara')
        self._set_integer_option_from_config('string_cutoff',
                section='yara')
        self._set_integer_option_from_config('identifier_cutoff',
                section='yara')

    def _set_options_from_arguments(self):
        if self.args.yara_directory:
            self.options.yara_directory = self.args.yara_directory
        if self.args.identifiers:
            self.options.identifiers = self.args.identifiers

    def _validate_options(self):
        # bangthreads >= 1
        if self.options.bangthreads < 1:
            self.options.bangthreads = self.defaults['bangthreads']

        # yara_directory must be declared
        if not self.options.yara_directory:
            self._error('Missing YARA directory')
        # yara_directory must exist
        if not os.path.exists(self.options.yara_directory):
            self._error("YARA directory %s does not exist, exiting"
                    % self.options.yara_directory)
        # .. be a directory
        if not os.path.isdir(self.options.yara_directory):
            self._error("YARA directory %s is not a directory, exiting"
                    % self.options.yara_directory)
