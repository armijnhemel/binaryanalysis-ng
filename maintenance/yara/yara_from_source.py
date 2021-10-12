#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes source code archives and generates YARA rules
'''

import sys
import os
import uuid
import argparse
import pathlib
import zipfile
import tarfile
import tempfile
import shutil
import hashlib
import subprocess
import datetime

# import some modules for dependencies, requires psycopg2 2.7+
import psycopg2
import psycopg2.extras

import packageurl

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

# lists of extenions for several programming language families
C_SRC_EXTENSIONS = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp',
                    '.hxx', '.h++', '.l', '.y', '.qml', '.s', '.txx', '.dts',
                    '.dtsi', ]

JAVA_SRC_EXTENSIONS = ['.java', '.jsp', '.groovy', '.scala', '.kt']

SRC_EXTENSIONS = C_SRC_EXTENSIONS + JAVA_SRC_EXTENSIONS

TAR_SUFFIX = ['.tbz2', '.tgz', '.txz', '.tlz', '.tz', '.gz', '.bz2', '.xz', '.lzma']

# YARA escape sequences
ESCAPE = str.maketrans({'"': '\\"',
                        '\\': '\\\\',
                        '\t': '\\t',
                        '\n': '\\n'})

NAME_ESCAPE = str.maketrans({'.': '_',
                             '-': '_'})


def generate_yara(yara_directory, metadata, functions, variables, strings, tags):
    generate_date = datetime.datetime.utcnow().isoformat()
    rule_uuid = uuid.uuid4()
    meta = '''
    meta:
        description = "Rule for %s"
        author = "Generated by BANG"
        date = "%s"
        uuid = "%s"
''' % (metadata['name'], generate_date, rule_uuid)

    for m in sorted(metadata):
        meta += '        %s = "%s"\n' % (m, metadata[m])

    #yara_file = yara_directory / ("%s-%s.yara" % (metadata['package'], metadata['name']))
    # TODO: origin and package?
    yara_file = yara_directory / ("%s-%s.yara" % (metadata['package'], metadata['language']))
    if tags == []:
        rule_name = 'rule rule_%s\n' % str(rule_uuid).translate(NAME_ESCAPE)
    else:
        rule_name = 'rule rule_%s: %s\n' % (str(rule_uuid).translate(NAME_ESCAPE), " ".join(tags))

    with yara_file.open(mode='w') as p:
        p.write(rule_name)
        p.write('{')
        p.write(meta)
        p.write('\n    strings:\n')

        # write the strings
        p.write("\n        // Extracted strings\n\n")
        counter = 1
        for s in sorted(strings):
            try:
                p.write("        $string%d = \"%s\"\n" % (counter, s))
                counter += 1
            except:
                pass

        # write the functions
        p.write("\n        // Extracted functions\n\n")
        counter = 1
        for s in sorted(functions):
            p.write("        $function%d = \"%s\"\n" % (counter, s))
            counter += 1

        # write the variable names
        p.write("\n        // Extracted variables\n\n")
        counter = 1
        for s in sorted(variables):
            p.write("        $variable%d = \"%s\"\n" % (counter, s))
            counter += 1

        # TODO: find good heuristics of how many identifiers should be matched
        p.write('\n    condition:\n')
        p.write('        all of them\n')
        p.write('\n}')
    return yara_file.name


def unpack_archive(temporary_directory, source_directory, archive, yara_env):
    '''Unpack an archive based on extension and extract identifiers'''
    unpack_dir = tempfile.TemporaryDirectory(dir=temporary_directory)
    tar_archive = source_directory / archive
    if tarfile.is_tarfile(tar_archive):
        try:
            tarchive = tarfile.open(name=tar_archive)
            members = tarchive.getmembers()
        except Exception as e:
            return

    identifiers_per_language = {}

    for m in members:
        extract_file = pathlib.Path(m.name)
        if extract_file.suffix.lower() in SRC_EXTENSIONS:
            if extract_file.suffix.lower() in C_SRC_EXTENSIONS:
                language = 'c'
                if 'c' not in identifiers_per_language:
                    identifiers_per_language['c'] = {}
                    identifiers_per_language['c']['strings'] = set()
                    identifiers_per_language['c']['functions'] = set()
                    identifiers_per_language['c']['variables'] = set()
            elif extract_file.suffix.lower() in JAVA_SRC_EXTENSIONS:
                language = 'java'
                if 'java' not in identifiers_per_language:
                    identifiers_per_language['java'] = {}
                    identifiers_per_language['java']['strings'] = set()
                    identifiers_per_language['java']['functions'] = set()
                    identifiers_per_language['java']['variables'] = set()

            # some path sanity checks (TODO: add more checks)
            if extract_file.is_absolute():
                pass
            else:
                member = tarchive.extractfile(m)

                # first run xgettext
                p = subprocess.Popen(['xgettext', '-a', '-o', '-', '--omit-header', '-'],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                (stdout, stderr) = p.communicate(member.read())

                if p.returncode == 0 and stdout != b'':
                    # process the output of standard out
                    lines = stdout.splitlines()
                    in_msg_id = False
                    msg_id = ''
                    for line in lines:
                        if line.strip() == b'':
                            continue
                        if line.startswith(b'#'):
                            # skip comments, hints, etc.
                            continue
                        try:
                            decoded_line = line.decode()
                            if decoded_line.startswith('msgid '):
                                msg_id += decoded_line[7:-1]
                                in_msg_id = True
                            elif decoded_line.startswith('msgstr '):
                                if len(msg_id) >= yara_env['string_min_cutoff'] and len(msg_id) <= yara_env['string_max_cutoff']:
                                    identifiers_per_language[language]['strings'].add(msg_id)
                                msg_id = ''
                                in_msg_id = False
                            else:
                                if in_msg_id:
                                    msg_id += decoded_line[1:-1]
                                    pass
                        except:
                            pass
                    if len(msg_id) >= yara_env['string_min_cutoff'] and len(msg_id) <= yara_env['string_max_cutoff']:
                        identifiers_per_language[language]['strings'].add(msg_id)

                # then run ctags. Unfortunately ctags cannot process
                # information from stdin so the file has to be extracted first
                tarchive.extract(m, path=unpack_dir.name)
                p = subprocess.Popen(['ctags', '-x', '-f', '-', unpack_dir.name / extract_file ],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                (stdout, stderr) = p.communicate()
                if p.returncode == 0 and stdout != b'':
                    lines = stdout.splitlines()
                    for line in lines:
                        try:
                            ctags_name, ctags_type = (line.decode().split(maxsplit=2))[:2]
                            if len(ctags_name) < yara_env['identifier_cutoff']:
                                continue
                            if ctags_type == 'field':
                                identifiers_per_language[language]['variables'].add(ctags_name)
                            elif ctags_type == 'variable':
                                # Kotlin uses variables, not fields
                                identifiers_per_language[language]['variables'].add(ctags_name)
                            elif ctags_type == 'method':
                                identifiers_per_language[language]['functions'].add(ctags_name)
                        except:
                                pass

    return identifiers_per_language


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", action="store", dest="cfg",
                        help="path to F-Droid configuration file", metavar="FILE")
    parser.add_argument("-s", "--source-directory", action="store", dest="source_directory",
                        help="path to directory with source code archives", metavar="DIR")
    args = parser.parse_args()

    # sanity checks for the source code directory
    if args.source_directory is None:
        parser.error("No source code directory provided, exiting")

    source_directory = pathlib.Path(args.source_directory)

    # the source directory should exist ...
    if not source_directory.exists():
        parser.error("File %s does not exist, exiting." % source_directory)

    # ... and should be a real directory
    if not source_directory.is_dir():
        parser.error("%s is not a directory, exiting." % source_directory)

    # sanity checks for the configuration file
    if args.cfg is None:
        parser.error("No configuration file provided, exiting")

    cfg = pathlib.Path(args.cfg)

    # the configuration file should exist ...
    if not cfg.exists():
        parser.error("File %s does not exist, exiting." % args.cfg)

    # ... and should be a real file
    if not cfg.is_file():
        parser.error("%s is not a regular file, exiting." % args.cfg)

    # read the configuration file. This is in YAML format
    try:
        configfile = open(args.cfg, 'r')
        config = load(configfile, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    #for i in ['database', 'general', 'yara']:
    for i in ['general', 'yara']:
        if i not in config:
            print("Invalid configuration file, section %s missing, exiting" % i,
                  file=sys.stderr)
            sys.exit(1)

    verbose = False
    if 'verbose' in config['general']:
        if isinstance(config['general']['verbose'], bool):
            verbose = config['general']['verbose']

    # directory for unpacking. By default this will be /tmp or whatever
    # the system default is.
    temporary_directory = None

    if 'tempdir' in config['general']:
        temporary_directory = pathlib.Path(config['general']['tempdir'])
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

    if 'yara_directory' not in config['yara']:
        print("yara_directory not defined in configuration, exiting",
              file=sys.stderr)
        sys.exit(1)

    yara_directory = pathlib.Path(config['yara']['yara_directory'])
    if not yara_directory.exists():
        print("yara_directory does not exist, exiting",
              file=sys.stderr)
        sys.exit(1)

    if not yara_directory.is_dir():
        print("yara_directory is not a valid directory, exiting",
              file=sys.stderr)
        sys.exit(1)

    # check if the yara directory is writable
    try:
        temp_name = tempfile.NamedTemporaryFile(dir=yara_directory)
        temp_name.close()
    except:
        print("yara_directory is not writable, exiting",
              file=sys.stderr)
        sys.exit(1)

    yara_output_directory = yara_directory / 'binary'

    yara_output_directory.mkdir(exist_ok=True)

    # test if ctags is available. This should be "universal ctags".
    if shutil.which('ctags') is None:
        print("ctags program not found, exiting",
              file=sys.stderr)
        sys.exit(1)

    # test if xgettext is available
    if shutil.which('xgettext') is None:
        print("xgettext program not found, exiting",
              file=sys.stderr)
        sys.exit(1)

    string_min_cutoff = 8
    if 'string_min_cutoff' in config['yara']:
        if isinstance(config['yara']['string_min_cutoff'], int):
            string_min_cutoff = config['yara']['string_min_cutoff']

    string_max_cutoff = 200
    if 'string_max_cutoff' in config['yara']:
        if isinstance(config['yara']['string_max_cutoff'], int):
            string_max_cutoff = config['yara']['string_max_cutoff']

    identifier_cutoff = 2
    if 'identifier_cutoff' in config['yara']:
        if isinstance(config['yara']['identifier_cutoff'], int):
            identifier_cutoff = config['yara']['identifier_cutoff']

    max_identifiers = 10000
    if 'max_identifiers' in config['yara']:
        if isinstance(config['yara']['max_identifiers'], int):
            max_identifiers = config['yara']['max_identifiers']

    tags = ['source']

    yara_env = {'verbose': verbose, 'string_min_cutoff': string_min_cutoff,
                'string_max_cutoff': string_max_cutoff,
                'identifier_cutoff': identifier_cutoff,
                'tags': tags, 'max_identifiers': max_identifiers}

    # get a list of archives, with associated metadata (purl) and then:
    # 1. unpack the archive
    # 2. walk all the files
    # 3. extract function names/variable names with ctags
    # 4. extract strings with xgettext
    # 5. generate YARA rules
    # walk the results directory
    for archive in source_directory.iterdir():
        identifiers_per_language = unpack_archive(temporary_directory, source_directory, archive, yara_env)

        for language in identifiers_per_language:
            # TODO: name is actually not correct, as it assumes
            # there is only one binary with that particular name
            # inside a package.
            metadata= {}
            metadata['name'] = archive.name
            metadata['sha256'] = ""
            metadata['package'] = archive.name
            metadata['language'] = language

            strings = identifiers_per_language[language]['strings']
            variables = identifiers_per_language[language]['variables']
            functions = identifiers_per_language[language]['functions']

            if not (strings == set() and variables == set() and functions == set()):
                yara_tags = yara_env['tags'] + [language]
                yara_name = generate_yara(yara_output_directory, metadata, functions, variables, strings, yara_tags)

if __name__ == "__main__":
    main()