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
# Licensed under the terms of the GNU Affero General Public License
# version 3
# SPDX-License-Identifier: AGPL-3.0-only

import os
import sys
import multiprocessing
import argparse
import stat
import configparser
import tempfile


class ObjectDict(dict):
    def __setattr__(self, name, value):
        self[name] = value

    def __getattr__(self, name):
        return self[name]


class BangScannerOptions:
    def __init__(self):
        self._set_default_options()
        self._parse_arguments()
        self._read_configuration_file()
        self._set_options_from_configuration_file()
        self._set_options_from_arguments()
        self._validate_options()

    def _set_default_options(self):
        self.defaults = {
            'cfg':
                os.path.join(os.path.dirname(sys.argv[0]), 'bang.config'),
            'baseunpackdirectory': '',
            'temporarydirectory': None,
            'removescandata': False,
            'removescandirectory': False,
            'createbytecounter': False,
            'createjson': True,
            'tlshmaximum': sys.maxsize,
            'writereport': True,
            'uselogging': True,
            'bangthreads': multiprocessing.cpu_count(),
            'checkpath': None,
        }
        self.options = ObjectDict(dict(self.defaults))

    def get(self):
        return self.options

    def _error(self, msg):
        print(msg, file=sys.stderr)
        sys.exit(1)

    def _parse_arguments(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-f", "--file",
                                action="store", dest="checkpath",
                                help="path to file/directory to check", metavar="FILE")
        self.parser.add_argument("-d", "--directory",
                                action="store", dest="checkpath",
                                help="path to file/directory to check",
                                metavar="DIR")
        self.parser.add_argument("-c", "--config",
                                action="store", dest="cfg",
                                help="path to configuration file",
                                metavar="FILE",
                                default=self.defaults['cfg'])
        self.parser.add_argument("-u", "--unpack-directory",
                                action="store", dest="baseunpackdirectory",
                                help="path to unpack directory",
                                metavar="FILE")
        self.parser.add_argument("-t", "--temporary-directory",
                                action="store", dest="temporarydirectory",
                                help="path to temporary directory",
                                metavar="FILE")
        self.args = self.parser.parse_args()
        self._check_configuration_file()

    def _check_configuration_file(self):
        if self.args.cfg is None:
            self.parser.error("No configuration file provided, exiting")
        # the configuration file should exist ...
        if not os.path.exists(self.args.cfg):
            self.parser.error("File %s does not exist, exiting." %
                                self.args.cfg)
        # ... and should be a real file
        if not stat.S_ISREG(os.stat(self.args.cfg).st_mode):
            self.parser.error("%s is not a regular file, exiting." %
                                self.args.cfg)

    def _read_configuration_file(self):
        # read the configuration file. This is in Windows INI format.
        environ = os.environ
        try:
            del environ['SHELL']
        except KeyError:
            pass
        self.config = configparser.ConfigParser(environ)
        try:
            configfile = open(self.args.cfg, 'r')
            self.config.read_file(configfile)
        except:
            self._error("Cannot open configuration file, exiting")

    def _set_string_option_from_config(self, option_name, section=None,
            option=None):
        if option is None:
            option = option_name
        try:
            v = self.config.get(section, option)
        except configparser.NoOptionError:
            return
        except configparser.NoSectionError:
            return
        except KeyError:
            return
        self.options[option_name] = v

    def _set_integer_option_from_config(self, option_name, section=None,
            option=None):
        if option is None:
            option = option_name
        try:
            v = int(self.config.get(section, option))
        except configparser.NoOptionError:
            return
        except KeyError:
            return
        except configparser.NoSectionError:
            return
        except ValueError:
            return
        self.options[option_name] = v

    def _set_boolean_option_from_config(self, option_name, section=None,
            option=None):
        if option is None:
            option = option_name
        try:
            v = self.config.get(section, option) == 'yes'
        except configparser.NoOptionError:
            return
        except configparser.NoSectionError:
            return
        except KeyError:
            return
        except ValueError:
            return
        self.options[option_name] = v

    def _set_options_from_configuration_file(self):
        self._set_string_option_from_config('baseunpackdirectory',
                section='configuration')
        self._set_string_option_from_config('temporarydirectory',
                section='configuration')
        self._set_integer_option_from_config('bangthreads',
                section='configuration', option='threads')
        self._set_boolean_option_from_config('removescandata',
                section='configuration')
        self._set_boolean_option_from_config('removescandirectory',
                section='configuration')
        self._set_boolean_option_from_config('createbytecounter',
                section='configuration', option='bytecounter')
        self._set_boolean_option_from_config('createjson',
                section='configuration', option='json')
        self._set_integer_option_from_config('tlshmaximum',
                section='configuration')
        self._set_boolean_option_from_config('writereport',
                section='configuration', option='report')
        self._set_boolean_option_from_config('uselogging',
                section='configuration', option='logging')

    def _set_options_from_arguments(self):
        self.options.checkpath = self.args.checkpath
        if self.args.baseunpackdirectory:
            self.options.baseunpackdirectory = self.args.baseunpackdirectory
        if self.args.temporarydirectory:
            self.options.temporarydirectory = self.args.temporarydirectory

    def _validate_options(self):
        # bangthreads >= 1
        if self.options.bangthreads < 1:
            self.options.bangthreads = self.defaults['bangthreads']

        # baseunpackdirectory must be declared
        if not self.options.baseunpackdirectory:
            self._error('Missing base unpack directory')
        # baseunpackdirectory must exist
        if not os.path.exists(self.options.baseunpackdirectory):
            self._error("Base unpack directory %s does not exist, exiting"
                    % self.options.baseunpackdirectory)
        # .. be a directory
        if not os.path.isdir(self.options.baseunpackdirectory):
            self._error("Base unpack directory %s is not a directory, exiting"
                    % self.options.baseunpackdirectory)
        # and writable
        if not self.check_if_directory_is_writable(self.options.baseunpackdirectory):
            self._error("Base unpack directory %s cannot be written to, exiting"
                    % self.options.baseunpackdirectory)
        self.options.baseunpackdirectory = os.path.realpath(self.options.baseunpackdirectory)
        # if temporarydirectory is defined
        if self.options.temporarydirectory is not None:
            # it must exist,
            if not os.path.exists(self.options.baseunpackdirectory):
                self._error("Temporary directory %s does not exist, exiting"
                        % self.options.temporarydirectory)
            # .. be a directory
            if not os.path.isdir(self.options.baseunpackdirectory):
                self._error("Temporary directory %s is not a directory, exiting"
                        % self.options.temporarydirectory)
            # .. and writable
            if not self.check_if_directory_is_writable(
                    self.options.baseunpackdirectory):
                self._error("Temporary directory %s cannot be written to, exiting"
                        % self.options.temporarydirectory)
        self.options.temporarydirectory = os.path.realpath(self.options.temporarydirectory)

        # either a check directory or a check file must be specified
        if self.options.checkpath is None:
            self._error("No file(s) provided to scan, exiting")
        if self.options.checkpath is not None:
            # the file to scan should exist ...
            if not os.path.exists(self.options.checkpath):
                self._error("Path %s does not exist, exiting."
                        % self.options.checkpath)
            # ... and should be a regular file or directory
            if not stat.S_ISREG(os.stat(self.options.checkpath).st_mode) and \
                    not os.path.isdir(self.options.checkpath):
                self._error("%s is not a regular file, exiting."
                        % self.options.checkpath)
            # ... and not empty
            if os.stat(self.options.checkpath).st_size == 0:
                self._error("%s is an empty file, exiting"
                        % self.options.checkpath)

    def check_if_directory_is_writable(self, dirname):
        try:
            testfile = tempfile.mkstemp(dir=dirname)
            os.unlink(testfile[1])
            return True
        except:
            return False
