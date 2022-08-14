#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
This script processes source code archives and adds
them to Meilisearch. Adapted from yara_from_source.py

$ python3 meilisearch_from_source.py -c meilisearch-config.yaml -s /tmp/bla/ -i ../yara/low_quality_identifiers.pickle
'''

import hashlib
import json
import multiprocessing
import os
import pathlib
import pickle
import queue
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

# import YAML module for the configuration
from yaml import load
from yaml import YAMLError
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import packageurl
import click
import meilisearch

# lists of extenions for several programming language families
C_SRC_EXTENSIONS = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp',
                    '.hxx', '.h++', '.l', '.y', '.qml', '.s', '.txx', '.dts',
                    '.dtsi', ]

JAVA_SRC_EXTENSIONS = ['.java', '.jsp', '.groovy', '.scala', '.kt']
JAVASCRIPT_SRC_EXTENSIONS = ['.js', '.dart']

SRC_EXTENSIONS = C_SRC_EXTENSIONS + JAVA_SRC_EXTENSIONS

TAR_SUFFIX = ['.tbz2', '.tgz', '.txz', '.tlz', '.tz', '.gz', '.bz2', '.xz', '.lzma']

def store_meili(resultqueue, meili_index):
    '''Grab results from the result queue, update
       where necessary and add to Meilisearch'''
    while True:
        results = resultqueue.get()
        update_documents = []
        new_documents = []

        # first check if there are any duplicates. If there
        # are, append it to the current results
        for result in results:
            try:
                meili_res = meili_index.get_document(result['id'])
                if result['paths'][0] not in meili_res['paths']:
                    meili_res['paths'] += result['paths']
                    update_documents.append(meili_res)
            except:
                new_documents.append(result)

        if new_documents != []:
            meili_index.update_documents(new_documents)
        if update_documents != []:
            meili_index.update_documents(update_documents)

        resultqueue.task_done()

def extract_identifiers(meiliqueue, resultqueue_ctags, resultqueue_strings, temporary_directory, source_directory, meili_env):
    '''Unpack a tar archive based on extension and extract identifiers'''

    while True:
        archive = meiliqueue.get()

        tar_archive = source_directory / archive
        try:
            tarchive = tarfile.open(name=tar_archive)
            members = tarchive.getmembers()
        except Exception:
            meiliqueue.task_done()
            continue

        # store the results per file
        results_ctags = []
        results_strings = []
        extracted = 0

        sha256_to_path = {}

        for member in members:
            extract_file = pathlib.Path(member.name)
            if extract_file.suffix.lower() in SRC_EXTENSIONS:
                extracted += 1
                break

        if extracted == 0:
            meiliqueue.task_done()
            continue

        unpack_dir = tempfile.TemporaryDirectory(dir=temporary_directory)
        tarchive.extractall(path=unpack_dir.name)
        for m in members:
            result_ctags = {}
            result_strings = {}

            extract_file = pathlib.Path(m.name)
            if extract_file.suffix.lower() in SRC_EXTENSIONS:
                if extract_file.suffix.lower() in C_SRC_EXTENSIONS:
                    language = 'c'
                elif extract_file.suffix.lower() in JAVA_SRC_EXTENSIONS:
                    language = 'java'

                result_ctags['language'] = language
                result_strings['language'] = language
                result_ctags['functions'] = set()
                result_ctags['variables'] = set()
                result_strings['strings'] = set()

                # some path sanity checks (TODO: add more checks)
                if extract_file.is_absolute():
                    pass
                else:
                    with open(unpack_dir.name / extract_file, 'rb') as member:
                        member_data = member.read()

                    member_hash = hashlib.new('sha256')
                    member_hash.update(member_data)
                    sha256 = member_hash.hexdigest()
                    result_ctags['id'] = sha256
                    result_strings['id'] = sha256
                    if sha256 in sha256_to_path:
                        sha256_to_path[sha256].append(str(extract_file))
                        continue
                    sha256_to_path[sha256] = [str(extract_file)]

                    # first run xgettext
                    p = subprocess.Popen(['xgettext', '-a', '-o', '-', '--no-wrap', '--omit-header', '-'],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                    (stdout, stderr) = p.communicate(member_data)

                    if p.returncode == 0 and stdout != b'':
                        # process the output of standard out
                        lines = stdout.splitlines()
                        for line in lines:
                            if line.strip() == b'':
                                continue
                            if line.startswith(b'#'):
                                # skip comments, hints, etc.
                                continue
                            try:
                                decoded_line = line.decode()
                                if decoded_line.startswith('msgid '):
                                    msg_id = decoded_line[7:-1]
                                    if len(msg_id) >= meili_env['string_min_cutoff'] and len(msg_id) <= meili_env['string_max_cutoff']:
                                        # ignore whitespace-only strings
                                        if re.match(r'^\s+$', msg_id) is None:
                                            result_strings['strings'].add(msg_id)
                            except Exception as e:
                                pass

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
                            except Exception:
                                continue
                            try:
                                ctags_name = ctags_json['name']
                                if len(ctags_name) < meili_env['identifier_cutoff']:
                                    continue
                                if ctags_json['kind'] == 'field':
                                    if language == 'java' and ctags_name in meili_env['lq_identifiers']['dex']['variables']:
                                        continue
                                    result_ctags['variables'].add(ctags_name)
                                elif ctags_json['kind'] == 'variable':
                                    if language == 'c' and ctags_name in meili_env['lq_identifiers']['elf']['variables']:
                                        continue
                                    if language == 'java' and ctags_name in meili_env['lq_identifiers']['dex']['variables']:
                                        continue
                                    # Kotlin uses variables, not fields
                                    result_ctags['variables'].add(ctags_name)
                                elif ctags_json['kind'] == 'method':
                                    if language == 'java' and ctags_name in meili_env['lq_identifiers']['dex']['functions']:
                                        continue
                                    result_ctags['functions'].add(ctags_name)
                                elif ctags_json['kind'] == 'function':
                                    if language == 'c' and ctags_name in meili_env['lq_identifiers']['elf']['functions']:
                                        continue
                                    result_ctags['functions'].add(ctags_name)
                            except:
                                pass

                    result_ctags['variables'] = list(result_ctags['variables'])
                    result_ctags['functions'] = list(result_ctags['functions'])
                    result_strings['strings'] = list(result_strings['strings'])

                    if not (result_ctags['variables'] == [] and result_ctags['functions'] == []):
                        results_ctags.append(result_ctags)
                    if result_strings['strings'] != []:
                        results_strings.append(result_strings)

        if results_ctags != []:
            for result in results_ctags:
                result['paths'] = sha256_to_path[result['id']]
            resultqueue_ctags.put(results_ctags)

        if results_strings != []:
            for result in results_strings:
                result['paths'] = sha256_to_path[result['id']]
            resultqueue_strings.put(results_strings)

        unpack_dir.cleanup()
        meiliqueue.task_done()


@click.command(short_help='process BANG result files and output Meilisearch data')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--source-directory', '-s', help='source code archive directory', type=click.Path(exists=True), required=True)
@click.option('--identifiers', '-i', help='pickle with low quality identifiers', type=click.File('rb'))
def main(config_file, source_directory, identifiers):

    # some sanity checks for Meilisearch
    client = meilisearch.Client('http://127.0.0.1:7700')
    meili_ctags_index = client.index('ctags')
    meili_strings_index = client.index('strings')

    try:
        health = client.health()
    except meilisearch.errors.MeiliSearchCommunicationError:
        print("Meilisearch not running, exiting...", file=sys.stderr)
        sys.exit(1)

    if health['status'] != 'available':
        print("Meilisearch not available, exiting...", file=sys.stderr)
        sys.exit(1)

    client.create_index('ctags', {'primaryKey': 'id'})
    client.create_index('ctags', {'primaryKey': 'id'})

    # only allow searches on 'functions' and 'variables'
    meili_ctags_index.update_settings({'searchableAttributes': [
          'functions',
          'variables',
        ]})

    meili_strings_index.update_settings({'searchableAttributes': [
          'strings',
        ]})

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

    # test if xgettext is available
    if shutil.which('xgettext') is None:
        print("xgettext program not found, exiting",
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

    meili_env = {'verbose': verbose, 'string_min_cutoff': string_min_cutoff,
                'string_max_cutoff': string_max_cutoff,
                'identifier_cutoff': identifier_cutoff,
                'max_identifiers': max_identifiers,
                'lq_identifiers': lq_identifiers}

    processmanager = multiprocessing.Manager()

    # create a queue for scanning files
    meiliqueue = processmanager.JoinableQueue(maxsize=0)
    meiliqueue = processmanager.JoinableQueue(maxsize=0)
    resultqueue_ctags = processmanager.JoinableQueue(maxsize=0)
    resultqueue_strings = processmanager.JoinableQueue(maxsize=0)
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
                                          args=(meiliqueue, resultqueue_ctags,
                                                resultqueue_strings,
                                                temporary_directory,
                                                source_directory, meili_env))
        processes.append(process)

    process = multiprocessing.Process(target=store_meili,
                                      args=(resultqueue_ctags, meili_ctags_index))
    processes.append(process)

    process = multiprocessing.Process(target=store_meili,
                                      args=(resultqueue_strings, meili_strings_index))
    processes.append(process)

    # start all the processes
    for process in processes:
        process.start()

    meiliqueue.join()
    resultqueue_ctags.join()
    resultqueue_strings.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()


if __name__ == "__main__":
    main()
