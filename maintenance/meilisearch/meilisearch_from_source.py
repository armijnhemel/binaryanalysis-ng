#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes source code archives and generates JSON
suitable to be loaded into Meilisearch. Adapted from yara_from_source.py
'''

import datetime
import hashlib
import json
import multiprocessing
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

import packageurl
import click

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
JAVASCRIPT_SRC_EXTENSIONS = ['.js', '.dart']

SRC_EXTENSIONS = C_SRC_EXTENSIONS + JAVA_SRC_EXTENSIONS

TAR_SUFFIX = ['.tbz2', '.tgz', '.txz', '.tlz', '.tz', '.gz', '.bz2', '.xz', '.lzma']


def extract_identifiers(meiliqueue, resultqueue, temporary_directory, source_directory, meili_env):
    '''Unpack a tar archive based on extension and extract identifiers'''

    while True:
        archive = meiliqueue.get()

        tar_archive = source_directory / archive
        try:
            tarchive = tarfile.open(name=tar_archive)
            members = tarchive.getmembers()
        except Exception as e:
            meiliqueue.task_done()
            continue

        # store the results per file and per language
        results = {}
        extracted = 0

        for m in members:
            extract_file = pathlib.Path(m.name)
            if extract_file.suffix.lower() in SRC_EXTENSIONS:
                extracted += 1
                break

        if extracted == 0:
            meiliqueue.task_done()
            continue

        unpack_dir = tempfile.TemporaryDirectory(dir=temporary_directory)
        tarchive.extractall(path=unpack_dir.name)
        for m in members:
            identifiers = {}

            extract_file = pathlib.Path(m.name)
            if extract_file.suffix.lower() in SRC_EXTENSIONS:
                if extract_file.suffix.lower() in C_SRC_EXTENSIONS:
                    language = 'c'
                elif extract_file.suffix.lower() in JAVA_SRC_EXTENSIONS:
                    language = 'java'

                identifiers['language'] = language
                identifiers['functions'] = set()
                identifiers['variables'] = set()

                # some path sanity checks (TODO: add more checks)
                if extract_file.is_absolute():
                    pass
                else:
                    member = open(unpack_dir.name / extract_file, 'rb')
                    member_data = member.read()
                    member.close()
                    member_hash = hashlib.new('sha256')
                    member_hash.update(member_data)
                    file_hash = member_hash.hexdigest()

                    # run ctags. Unfortunately ctags cannot process
                    # information from stdin so the file has to be extracted first
                    p = subprocess.Popen(['ctags', '--output-format=json', '-f', '-', unpack_dir.name / extract_file ],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                    (stdout, stderr) = p.communicate()
                    if p.returncode == 0 and stdout != b'':
                        lines = stdout.splitlines()
                        for line in lines:
                            try:
                                ctags_json = json.loads(line)
                            except Exception as e:
                                continue
                            try:
                                ctags_name = ctags_json['name']
                                if len(ctags_name) < meili_env['identifier_cutoff']:
                                    continue
                                if ctags_json['kind'] == 'field':
                                    identifiers['variables'].add(ctags_name)
                                elif ctags_json['kind'] == 'variable':
                                    # Kotlin uses variables, not fields
                                    identifiers['variables'].add(ctags_name)
                                elif ctags_json['kind'] == 'method':
                                    identifiers['functions'].add(ctags_name)
                                elif ctags_json['kind'] == 'function':
                                    identifiers['functions'].add(ctags_name)
                            except:
                                pass
                results[extract_file] = identifiers

        for result in results:
            identifiers = results[result]

            # generate json for Meilisearch and add to the result queue
            if not (identifiers['variables'] == set() and identifiers['functions'] == set()):
                pass

        unpack_dir.cleanup()
        meiliqueue.task_done()


@click.command(short_help='process BANG result files and output Meilisearch data')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--source-directory', '-s', help='source code archive directory', type=click.Path(exists=True), required=True)
@click.option('--identifiers', '-i', help='pickle with low quality identifiers', type=click.File('rb'))
def main(config_file, source_directory, identifiers):

    source_directory = pathlib.Path(source_directory)

    # should be a real directory
    if not source_directory.is_dir():
        print("%s is not a directory, exiting." % source_directory, file=sys.stderr)
        sys.exit(1)

    lq_identifiers = {'elf': {'functions': [], 'variables': []},
                      'dex': {'functions': [], 'variables': []}}

    # read the pickle with identifiers
    if identifiers is not None:
        try:
            lq_identifiers = pickle.load(identifiers)
        except:
            pass

    # read the configuration file. This is in YAML format
    try:
        config = load(config_file, Loader=Loader)
    except (YAMLError, PermissionError):
        print("Cannot open configuration file, exiting", file=sys.stderr)
        sys.exit(1)

    # some sanity checks:
    for i in ['general', 'meilisearch']:
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

    # test if ctags is available. This should be "universal ctags".
    if shutil.which('ctags') is None:
        print("ctags program not found, exiting",
              file=sys.stderr)
        sys.exit(1)

    threads = multiprocessing.cpu_count()
    if 'threads' in config['general']:
        if isinstance(config['general']['threads'], int):
            threads = config['general']['threads']

    # always have a minimum of 2 threads
    if threads == 1:
        threads = 2

    string_min_cutoff = 8
    if 'string_min_cutoff' in config['meilisearch']:
        if isinstance(config['meilisearch']['string_min_cutoff'], int):
            string_min_cutoff = config['meilisearch']['string_min_cutoff']

    string_max_cutoff = 200
    if 'string_max_cutoff' in config['meilisearch']:
        if isinstance(config['meilisearch']['string_max_cutoff'], int):
            string_max_cutoff = config['meilisearch']['string_max_cutoff']

    identifier_cutoff = 2
    if 'identifier_cutoff' in config['meilisearch']:
        if isinstance(config['meilisearch']['identifier_cutoff'], int):
            identifier_cutoff = config['meilisearch']['identifier_cutoff']

    max_identifiers = 10000
    if 'max_identifiers' in config['meilisearch']:
        if isinstance(config['meilisearch']['max_identifiers'], int):
            max_identifiers = config['meilisearch']['max_identifiers']

    tags = ['source']

    meili_env = {'verbose': verbose, 'string_min_cutoff': string_min_cutoff,
                'string_max_cutoff': string_max_cutoff,
                'identifier_cutoff': identifier_cutoff,
                'tags': tags, 'max_identifiers': max_identifiers}

    processmanager = multiprocessing.Manager()

    # create a queue for scanning files
    meiliqueue = processmanager.JoinableQueue(maxsize=0)
    resultqueue = processmanager.JoinableQueue(maxsize=0)
    processes = []

    # walk the archives directory
    for archive in source_directory.iterdir():
        tar_archive = source_directory / archive
        if not tarfile.is_tarfile(tar_archive):
            continue
        meiliqueue.put(archive)

    # create processes for unpacking archives
    for i in range(0, threads - 1):
        process = multiprocessing.Process(target=extract_identifiers,
                                          args=(meiliqueue, resultqueue,
                                                temporary_directory,
                                                source_directory, meili_env))
        processes.append(process)

    # start all the processes
    for process in processes:
        process.start()

    meiliqueue.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()


if __name__ == "__main__":
    main()
