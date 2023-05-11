#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright 2021-2022 - Armijn Hemel
# Licensed under the terms of the GNU Affero General Public License version 3
# SPDX-License-Identifier: AGPL-3.0-only

'''
Process source code archives, extracts identifiers and output as JSON
'''

import datetime
import hashlib
import json
import multiprocessing
import pathlib
import pickle
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid
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

from yara_config import YaraConfig, YaraConfigException

# lists of extenions for several programming language families
C_SRC_EXTENSIONS = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.h', '.hh', '.hpp',
                    '.hxx', '.h++', '.l', '.y', '.qml', '.s', '.txx', '.dts',
                    '.dtsi', ]

JAVA_SRC_EXTENSIONS = ['.java', '.jsp', '.groovy', '.scala', '.kt']
JAVASCRIPT_SRC_EXTENSIONS = ['.js', '.dart']

SRC_EXTENSIONS = C_SRC_EXTENSIONS + JAVA_SRC_EXTENSIONS

TAR_SUFFIX = ['.tbz2', '.tgz', '.txz', '.tlz', '.tz', '.gz', '.bz2', '.xz', '.lzma']

REMOVE_CHARACTERS = ['\a', '\b', '\v', '\f', '\x01', '\x02', '\x03', '\x04',
                     '\x05', '\x06', '\x0e', '\x0f', '\x10', '\x11', '\x12',
                     '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19',
                     '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x7f']

REMOVE_CHARACTERS_TABLE = str.maketrans({'\a': '', '\b': '', '\v': '',
                                         '\f': '', '\x01': '', '\x02': '',
                                         '\x03': '', '\x04': '', '\x05': '',
                                         '\x06': '', '\x0e': '', '\x0f': '',
                                         '\x10': '', '\x11': '', '\x12': '',
                                         '\x13': '', '\x14': '', '\x15': '',
                                         '\x16': '', '\x17': '', '\x18': '',
                                         '\x19': '', '\x1a': '', '\x1b': '',
                                         '\x1c': '', '\x1d': '', '\x1e': '',
                                         '\x1f': '', '\x7f': ''
                                        })


def extract_identifiers(process_queue, temporary_directory, source_directory, json_output_directory, extraction_env, package_meta_information):
    '''Unpack a tar archive based on extension and extract identifiers'''

    heuristics = {}
    while True:
        purl, version, archive = process_queue.get()

        try:
            tarchive = tarfile.open(name=archive)
            members = tarchive.getmembers()
        except Exception as e:
            process_queue.task_done()
            continue

        identifiers_per_language = {}

        identifiers_per_language['c'] = {}
        identifiers_per_language['c']['strings'] = set()
        identifiers_per_language['c']['functions'] = set()
        identifiers_per_language['c']['variables'] = set()

        identifiers_per_language['java'] = {}
        identifiers_per_language['java']['strings'] = set()
        identifiers_per_language['java']['functions'] = set()
        identifiers_per_language['java']['variables'] = set()

        extracted = 0

        for m in members:
            extract_file = pathlib.Path(m.name)
            if extract_file.suffix.lower() in SRC_EXTENSIONS:
                extracted += 1
                break

        if extracted == 0:
            process_queue.task_done()
            continue

        with open(archive, 'rb') as package_data:
            archive_hash = hashlib.new('sha256')
            archive_hash.update(package_data.read())
            package_hash = archive_hash.hexdigest()

        unpack_dir = tempfile.TemporaryDirectory(dir=temporary_directory)
        tarchive.extractall(path=unpack_dir.name)
        for m in members:
            extract_file = pathlib.Path(m.name)
            if extract_file.suffix.lower() in SRC_EXTENSIONS:
                if extract_file.suffix.lower() in C_SRC_EXTENSIONS:
                    language = 'c'
                elif extract_file.suffix.lower() in JAVA_SRC_EXTENSIONS:
                    language = 'java'

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

                    # TODO: lookup hash in some database to detect third
                    # party/external components so they can be ignored

                    # first run xgettext
                    p = subprocess.Popen(['xgettext', '-a', '-o', '-', '--no-wrap', '--no-location', '--omit-header', '-'],
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
                            if line.startswith(b'msgstr'):
                                continue
                            try:
                                decoded_line = line.decode()

                                if decoded_line.startswith('msgid '):
                                    msg_id = decoded_line[7:-1]
                                else:
                                    msg_id = decoded_line[1:-1]

                                # this is a bit of a horrible hack
                                # https://stackoverflow.com/questions/1885181/how-to-un-escape-a-backslash-escaped-string
                                try:
                                    msg_id = msg_id.encode('utf-8', 'backslashreplace').decode('unicode-escape')
                                except:
                                    continue

                                # backslashes should be replaced now so
                                # split on newlines
                                msg_ids = msg_id.splitlines()
                                for m in msg_ids:
                                    for rc in REMOVE_CHARACTERS:
                                        if rc in m:
                                            m = m.translate(REMOVE_CHARACTERS_TABLE)

                                    if m == '':
                                        continue

                                    # ignore whitespace-only strings
                                    if re.match(r'^\s+$', m) is not None:
                                        continue

                                    identifiers_per_language[language]['strings'].add(m)
                            except:
                                pass

                    # then run ctags. Unfortunately ctags cannot process
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
                                if ctags_json['kind'] == 'field':
                                    identifiers_per_language[language]['variables'].add(ctags_name)
                                elif ctags_json['kind'] == 'variable':
                                    # Kotlin uses variables, not fields
                                    identifiers_per_language[language]['variables'].add(ctags_name)
                                elif ctags_json['kind'] == 'method':
                                    identifiers_per_language[language]['functions'].add(ctags_name)
                                elif ctags_json['kind'] == 'function':
                                    identifiers_per_language[language]['functions'].add(ctags_name)
                            except:
                                pass

        for language in identifiers_per_language:
            metadata= {}
            metadata['archive'] = archive.name
            metadata['sha256'] = package_hash
            metadata['package'] = package_meta_information['package']
            metadata['language'] = language
            metadata['version'] = purl.version
            metadata['packageurl'] = purl.to_string()
            website = package_meta_information.get('website')
            if website is not None:
                metadata['website'] = website
            cpe = package_meta_information.get('cpe')
            if cpe is not None:
                metadata['cpe'] = cpe
            cpe23 = package_meta_information.get('cpe23')
            if cpe23 is not None:
                metadata['cpe23'] = cpe23

            strings = sorted(identifiers_per_language[language]['strings'])
            variables = sorted(identifiers_per_language[language]['variables'])
            functions = sorted(identifiers_per_language[language]['functions'])

            if not (strings == [] and variables == [] and functions == []):
                # write results to a JSON file for later processing
                json_file = json_output_directory / ("%s-%s.json" % (archive.name, language))
                with open(json_file, 'w') as dump_file:
                    json.dump({'metadata': metadata, 'strings': strings,
                              'variables': variables, 'functions': functions}, dump_file, indent=4)

        unpack_dir.cleanup()
        process_queue.task_done()


@click.command(short_help='process BANG result files and output YARA')
@click.option('--config-file', '-c', required=True, help='configuration file', type=click.File('r'))
@click.option('--source-directory', '-s', required=True, help='source code archive directory', type=click.Path(exists=True))
@click.option('--meta', '-m', required=True, help='file with meta information about a package', type=click.File('r'))
def main(config_file, source_directory, meta):
    # check if ctags is available. This should be "universal ctags"
    # not "exuberant ctags"
    if shutil.which('ctags') is None:
        print("ctags program not found, exiting",
              file=sys.stderr)
        sys.exit(1)

    # check if xgettext is available
    if shutil.which('xgettext') is None:
        print("xgettext program not found, exiting",
              file=sys.stderr)
        sys.exit(1)

    source_directory = pathlib.Path(source_directory)

    if not source_directory.is_dir():
        print("%s is not a directory, exiting." % source_directory, file=sys.stderr)
        sys.exit(1)

    # parse the configuration
    json_config = YaraConfig(config_file)
    try:
        extraction_env = json_config.parse()
    except YaraConfigException as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    # parse the package meta information
    try:
        package_meta_information = load(meta, Loader=Loader)
    except (YAMLError, PermissionError) as e:
        print("invalid YAML:", e.args, file=sys.stderr)
        sys.exit(1)

    if not 'package' in package_meta_information:
        print("'package' missing in YAML", file=sys.stderr)
        sys.exit(1)

    if not 'releases' in package_meta_information:
        print("'releases' missing in YAML", file=sys.stderr)
        sys.exit(1)

    package = package_meta_information['package']

    # first verify that the top level package url is valid
    try:
        top_purl = packageurl.PackageURL.from_string(package_meta_information['packageurl'])
    except ValueError:
        print("%s not a valid packageurl" % package_meta_information['packageurl'], file=sys.stderr)
        sys.exit(1)

    packages = []

    # some sanity checks for the files defined in the metadata
    for release in package_meta_information['releases']:
        for release_version in release:
            release_filename = release[release_version]
            if not (source_directory / release_filename).exists():
                print("%s does not exist" % (source_directory / release_filename), file=sys.stderr)
                if extraction_env['error_fatal']:
                    sys.exit(1)
                    continue
            packages.append((release_version, release_filename))

    json_output_directory = extraction_env['json_directory'] / package

    json_output_directory.mkdir(exist_ok=True)

    processmanager = multiprocessing.Manager()

    # create a queue for scanning files
    process_queue = processmanager.JoinableQueue(maxsize=0)
    processes = []

    # walk the archives directory, only support tar files now
    for archive in packages:
        version, archive_name = archive

        # verify that the version is a valid package url
        try:
            purl = packageurl.PackageURL.from_string(version)
        except ValueError:
            print("%s not a valid packageurl" % version, file=sys.stderr)
            if extraction_env['error_fatal']:
                sys.exit(1)
            continue
        # sanity checks to verify that the top level purl matches
        if purl.type != top_purl.type:
            print("type '%s' does not match top level type '%s'" % (purl.type, top_purl.type),
                  file=sys.stderr)
            if extraction_env['error_fatal']:
                sys.exit(1)
            continue
        if purl.name != top_purl.name:
            print("name '%s' does not match top level name '%s'" % (purl.name, top_purl.name),
                  file=sys.stderr)
            if extraction_env['error_fatal']:
                sys.exit(1)
            continue

        tar_archive = source_directory / archive_name
        if not tarfile.is_tarfile(tar_archive):
            continue
        process_queue.put((purl, version, tar_archive))

    # create processes for unpacking archives
    for i in range(0, extraction_env['threads']):
        process = multiprocessing.Process(target=extract_identifiers,
                                          args=(process_queue, extraction_env['temporary_directory'],
                                                source_directory, json_output_directory,
                                                extraction_env, package_meta_information))
        processes.append(process)

    # start all the processes
    for process in processes:
        process.start()

    process_queue.join()

    # Done processing, terminate processes
    for process in processes:
        process.terminate()


if __name__ == "__main__":
    main()
