#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions
# Licensed under the terms of the GNU General Public License version 3
# SPDX-License-Identifier: GPL-3.0-only

'''
This script generates a YARA rule from a JSON file containing symbols
and strings that were extracted from a binary using BANG.

Use bang_to_json.py to generate the JSON file.
'''

import copy
import datetime
import json
import pathlib
import pickle
import re
import sys
import uuid

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

# ignore object files (regular and GHC specific)
IGNORED_ELF_SUFFIXES = ['.o', '.p_o']

# YARA escape sequences
ESCAPE = str.maketrans({'"': '\\"',
                        '\\': '\\\\',
                        '\t': '\\t',
                        '\n': '\\n'})

NAME_ESCAPE = str.maketrans({'.': '_',
                             '-': '_'})


def generate_yara(yara_file, metadata, functions, variables, strings,
                  tags, num_strings, num_funcs, num_vars, fullword,
                  yara_operator, bang_type):
    '''Generate YARA rules from identifiers. Returns a UUID for a rule.'''
    generate_date = datetime.datetime.utcnow().isoformat()
    rule_uuid = uuid.uuid4()
    total_identifiers = len(functions) + len(variables) + len(strings)
    meta = f'''
    meta:
        description = "Rule for {metadata['name']}"
        author = "Generated by BANG"
        date = "{generate_date}"
        uuid = "{rule_uuid}"
        total_identifiers = "{total_identifiers}"
        identifiers_from = "{bang_type}"
'''

    for m in sorted(metadata):
        meta += f'        {m} = "{metadata[m]}"\n'

    # create a tags string for the rule if there are any tags.
    # These can be used by YARA to only run specific rules.
    tags_string = ''
    if tags != []:
        tags_string = ": " + " ".join(tags)

    rule = str(rule_uuid).translate(NAME_ESCAPE)
    rule_name = f'rule rule_{rule}{tags_string}\n'

    with yara_file.open(mode='w') as p:
        p.write(rule_name)
        p.write('{')
        p.write(meta)
        p.write('\n    strings:\n')

        # First write all strings
        if strings != []:
            p.write("\n        // Extracted strings\n\n")
            counter = 1
            for s in strings:
                try:
                    s_translated = s.translate(ESCAPE)
                    p.write(f"        $string{counter} = \"{s_translated}\"{fullword}\n")
                    counter += 1
                except:
                    pass

        # Then write the functions
        if functions != []:
            p.write("\n        // Extracted functions\n\n")
            counter = 1
            for s in sorted(functions):
                p.write(f"        $function{counter} = \"{s}\"{fullword}\n")
                counter += 1

        # Then the variable names
        if variables != []:
            p.write("\n        // Extracted variables\n\n")
            counter = 1
            for s in sorted(variables):
                p.write(f"        $variable{counter} = \"{s}\"{fullword}\n")
                counter += 1

        # Finally write the conditions
        p.write('\n    condition:\n')
        if strings != []:
            p.write(f'        {num_strings} of ($string*)')

            if not (functions == [] and variables == []):
                p.write(f' {yara_operator}\n')
            else:
                p.write('\n')
        if functions != []:
            p.write(f'        {num_funcs} of ($function*)')

            if variables != []:
                p.write(' %s\n' % yara_operator)
            else:
                p.write('\n')
        if variables != []:
            p.write(f'        {num_vars} of ($variable*)')
        p.write('\n}')

    # return the UUID for the rule so it can be recorded
    return rule_uuid

@click.group()
def app():
    pass

@app.command(short_help='process a BANG JSON result file and output YARA rules for binaries')
@click.option('--config-file', '-c', required=True, help='configuration file',
              type=click.File('r'))
@click.option('--json', '-j', 'result_json', help='BANG JSON result file',
              type=click.File('r'), required=True)
@click.option('--identifiers', '-i', help='pickle with low quality identifiers',
              required=True, type=click.File('rb'))
@click.option('--no-functions', is_flag=True, default=False, help="do not use functions")
@click.option('--no-variables', is_flag=True, default=False, help="do not use variables")
@click.option('--no-strings', is_flag=True, default=False, help="do not use strings")
def binary(config_file, result_json, identifiers, no_functions, no_variables, no_strings):
    bang_type = 'binary'

    # parse the configuration
    yara_config = YaraConfig(config_file)
    yara_env = yara_config.parse()

    # define a data structure with low quality
    # identifiers for ELF and Dex
    lq_identifiers = {'elf': {'functions': [], 'variables': [], 'strings': []},
                      'dex': {'functions': [], 'variables': [], 'strings': []}}

    # read the pickle with low quality identifiers
    if identifiers is not None:
        try:
            lq_identifiers = pickle.load(identifiers)
        except pickle.UnpicklingError:
            pass

    yara_directory = yara_env['yara_directory'] / 'binary'

    yara_directory.mkdir(exist_ok=True)

    # load the JSON
    try:
        bang_data = json.load(result_json)
    except:
        print("Could not open JSON, exiting", file=sys.stderr)
        sys.exit(1)

    # no need to generate any YARA files for empty files
    if bang_data['metadata']['sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
        print("Cannot generate YARA file for empty file, exiting", file=sys.stderr)
        sys.exit(1)

    if 'labels' in bang_data:
        if 'ocaml' in bang_data['labels']:
            if yara_env['ignore_ocaml']:
                print("OCAML file found that should be ignored, exiting", file=sys.stderr)
                sys.exit()
        if 'elf' in bang_data['labels']:
            suffix = pathlib.Path(bang_data['metadata']['name']).suffix

            if suffix in IGNORED_ELF_SUFFIXES:
                print("Ignored suffix, exiting", file=sys.stderr)
                sys.exit()

            if 'static' in bang_data['labels']:
                if not 'linuxkernelmodule' in bang_data['labels']:
                    # TODO: clean up for linux kernel modules
                    print("Static ELF binary not supported yet, exiting", file=sys.stderr)
                    sys.exit()

    tags = bang_data.get('tags', [])

    # store the type of executable
    if 'elf' in bang_data['labels']:
        exec_type = 'elf'
    elif 'dex' in bang_data['labels']:
        exec_type = 'dex'
    else:
        exec_type = None

    if not exec_type:
        print("Unsupported executable type, exiting", file=sys.stderr)
        sys.exit(2)

    # set metadata
    metadata = bang_data['metadata']

    strings = set()
    functions = set()
    variables = set()

    heuristics = yara_env['heuristics']

    if exec_type == 'elf':
        if 'telfhash' in bang_data['metadata']:
            metadata['telfhash'] = bang_data['metadata']['telfhash']

        # process strings
        if bang_data['strings'] != [] and not no_strings:
            for s in bang_data['strings']:
                if len(s) < yara_env['string_minimum_length']:
                    continue
                if len(s) > yara_env['string_maximum_length']:
                    continue
                # ignore whitespace-only strings
                if re.match(r'^\s+$', s) is None:
                    if s in lq_identifiers['elf']['strings']:
                        continue
                    strings.add(s.translate(ESCAPE))

        # process symbols, split in functions and variables
        if bang_data['symbols'] != []:
            for s in bang_data['symbols']:
                if s['section_index'] == 0:
                    continue
                if yara_env['ignore_weak_symbols']:
                    if s['binding'] == 'weak':
                        continue
                if len(s['name']) < yara_env['identifier_cutoff']:
                    continue
                if '@@' in s['name']:
                    identifier_name = s['name'].rsplit('@@', 1)[0]
                elif '@' in s['name']:
                    identifier_name = s['name'].rsplit('@', 1)[0]
                else:
                    identifier_name = s['name']
                if s['type'] == 'func' and not no_functions:
                    if identifier_name in lq_identifiers['elf']['functions']:
                        continue
                    functions.add(identifier_name)
                elif s['type'] == 'object' and not no_variables:
                    if identifier_name in lq_identifiers['elf']['variables']:
                        continue
                    variables.add(identifier_name)

        # check if the number of identifiers passes a threshold.
        # If not assume that there are no identifiers.
        if len(strings) < heuristics['strings_extracted']:
            strings = set()
        if len(functions) < heuristics['functions_extracted']:
            functions = set()
        if len(variables) < heuristics['variables_extracted']:
            variables = set()

    elif exec_type == 'dex':
        for c in bang_data['classes']:
            # process methods/functions
            if not no_functions:
                for method in c['methods']:
                    # ignore whitespace-only methods
                    if len(method['name']) < yara_env['identifier_cutoff']:
                        continue
                    if re.match(r'^\s+$', method['name']) is not None:
                        continue
                    if method['name'] in ['<init>', '<clinit>']:
                        continue
                    if method['name'].startswith('access$'):
                        continue
                    if method['name'] in lq_identifiers['dex']['functions']:
                        continue
                    functions.add(method['name'])

            # process strings
            if not no_strings:
                for method in c['methods']:
                    for s in method['strings']:
                        if len(s) < yara_env['string_minimum_length']:
                            continue
                        if len(s) > yara_env['string_maximum_length']:
                            continue
                        # ignore whitespace-only strings
                        if re.match(r'^\s+$', s) is None:
                            strings.add(s.translate(ESCAPE))

            # process fields/variables
            if not no_variables:
                for field in c['fields']:
                    # ignore whitespace-only methods
                    if len(field['name']) < yara_env['identifier_cutoff']:
                        continue
                    if re.match(r'^\s+$', field['name']) is not None:
                        continue

                    if field['name'] in lq_identifiers['dex']['variables']:
                        continue
                    variables.add(field['name'])

    # do not generate a YARA file if there is no data
    if strings == set() and variables == set() and functions == set():
        return

    yara_tags = sorted(set(tags + [exec_type]))

    total_identifiers = len(functions) + len(variables) + len(strings)

    # by default YARA has a limit of 10,000 identifiers
    # TODO: see which ones can be ignored.
    if total_identifiers > yara_env['max_identifiers']:
        pass

    yara_file = yara_directory / (f"{metadata['name']}-{metadata['sha256']}.yara")

    fullword = ''
    if yara_env['fullword']:
        fullword = ' fullword'

    num_strings = num_funcs = num_vars = 'any'

    if len(strings) >= heuristics['strings_minimum_present']:
        num_strings = str(int(max(len(strings)//heuristics['strings_percentage'], heuristics['strings_matched'])))

    if len(functions) >= heuristics['functions_minimum_present']:
        num_funcs = str(int(max(len(functions)//heuristics['functions_percentage'], heuristics['functions_matched'])))

    if len(variables) >= heuristics['variables_minimum_present']:
        num_vars = str(int(max(len(variables)//heuristics['variables_percentage'], heuristics['variables_matched'])))

    rule_uuid = generate_yara(yara_file, metadata, sorted(functions), sorted(variables),
                              sorted(strings), yara_tags, num_strings, num_funcs, num_vars,
                              fullword, yara_env['operator'], bang_type)

@app.command(short_help='process JSON files with identifiers extracted from source code and output YARA rules')
@click.option('--config-file', '-c', required=True, help='configuration file',
              type=click.File('r'))
@click.option('--json-directory', '-j', required=True, help='JSON file directory',
              type=click.Path(exists=True, path_type=pathlib.Path))
@click.option('--identifiers', '-i', required=True, help='pickle with low quality identifiers',
              type=click.File('rb'))
@click.option('--meta', '-m', required=True, help='file with meta information about versions of a package',
              type=click.File('r'))
@click.option('--no-functions', is_flag=True, default=False, help="do not use functions")
@click.option('--no-variables', is_flag=True, default=False, help="do not use variables")
@click.option('--no-strings', is_flag=True, default=False, help="do not use strings")
@click.argument('versions', nargs=-1)
def source(config_file, json_directory, identifiers, meta, no_functions, no_variables, no_strings, versions):
    '''Generate YARA files from identifiers extracted from source code.

       Optionally specify VERSIONS to only generate YARA files for a subset of package versions.'''
    bang_type = "source"

    # should be a real directory
    if not json_directory.is_dir():
        print(f"{json_directory} is not a directory, exiting.", file=sys.stderr)
        sys.exit(1)

    # parse the configuration
    yara_config = YaraConfig(config_file)
    try:
        yara_env = yara_config.parse()
    except YaraConfigException as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    # parse the package meta information
    try:
        package_meta_information = load(meta, Loader=Loader)
    except (YAMLError, PermissionError) as e:
        print("invalid YAML:", e.args, file=sys.stderr)
        sys.exit(1)

    packages = []

    package = package_meta_information['package']

    # first verify that the top level package url in the metadata is valid
    try:
        top_purl = packageurl.PackageURL.from_string(package_meta_information['packageurl'])
    except ValueError:
        print(f"{package_meta_information['packageurl']} not a valid packageurl", file=sys.stderr)
        sys.exit(1)

    package_versions = set()

    for release in package_meta_information['releases']:
        for version in release:
            # verify that the version is a valid package url
            try:
                purl = packageurl.PackageURL.from_string(version)
            except ValueError:
                print(f"{version} not a valid packageurl", file=sys.stderr)
                if yara_env['error_fatal']:
                    sys.exit(1)
                continue
            # sanity checks to verify that the top level purl matches
            if purl.type != top_purl.type:
                print(f"type '{purl.type}' does not match top level type '{top_purl.type}'",
                      file=sys.stderr)
                if yara_env['error_fatal']:
                    sys.exit(1)
                continue
            if purl.name != top_purl.name:
                print(f"name '{purl.name}' does not match top level name '{top_purl.name}'",
                      file=sys.stderr)
                if yara_env['error_fatal']:
                    sys.exit(1)
                continue
            if versions != ():
                if purl.version in versions:
                    package_versions.add(version)
            else:
                package_versions.add(version)

    # mapping for low quality identifiers. C is mapped to ELF,
    # Java is mapped to Dex. TODO: use something a bit more sensible.
    lq_identifiers = {'elf': {'functions': [], 'variables': [], 'strings': []},
                      'dex': {'functions': [], 'variables': [], 'strings': []}}

    # read the pickle with identifiers
    if identifiers is not None:
        try:
            lq_identifiers = pickle.load(identifiers)
        except pickle.UnpicklingError:
            pass

    # expand yara_env with source scanning specific values
    yara_env['lq_identifiers'] = lq_identifiers

    yara_directory = yara_env['yara_directory'] / 'src' / top_purl.type / top_purl.name

    # store the languages and store the minimum per
    # language, relevant for heuristics
    languages = set()
    min_per_language = {}

    # keep track of all the identifiers for a package
    all_identifiers_per_language = {}

    tags = ['source']

    # first instantiate the heuristics
    heuristics = copy.deepcopy(yara_env['heuristics'])

    fullword = ''
    if yara_env['fullword']:
        fullword = ' fullword'

    # process all the JSON files in the directory
    for result_file in json_directory.glob('**/*'):
        # sanity check for the package
        try:
            with open(result_file, 'r') as json_archive:
                json_results = json.load(json_archive)

                if json_results['metadata']['package'] == package:
                    if json_results['metadata'].get('packageurl') in package_versions:
                        yara_directory.mkdir(parents=True, exist_ok=True)
                        strings = set()
                        functions = set()
                        variables = set()

                        metadata = json_results['metadata']
                        metadata['name'] = metadata['archive']

                        packages.append(result_file)
                        language = json_results['metadata']['language']
                        languages.add(language)

                        if language not in min_per_language:
                            min_per_language[language] = {}
                            min_per_language[language]['strings'] = sys.maxsize
                            min_per_language[language]['variables'] = sys.maxsize
                            min_per_language[language]['functions'] = sys.maxsize

                            all_identifiers_per_language[language] = {}
                            all_identifiers_per_language[language]['strings'] = set()
                            all_identifiers_per_language[language]['functions'] = set()
                            all_identifiers_per_language[language]['variables'] = set()

                        for string in json_results['strings']:
                            if len(string) >= yara_env['string_minimum_length'] and len(string) <= yara_env['string_maximum_length']:
                                if language == 'c':
                                    if string in lq_identifiers['elf']['strings']:
                                        continue
                                all_identifiers_per_language[language]['strings'].add(string)
                                strings.add(string)

                        for function in json_results['functions']:
                            if len(function) < yara_env['identifier_cutoff']:
                                continue
                            if language == 'c':
                                if function in lq_identifiers['elf']['functions']:
                                    continue
                            all_identifiers_per_language[language]['functions'].add(function)
                            functions.add(function)

                        for variable in json_results['variables']:
                            if len(variable) < yara_env['identifier_cutoff']:
                                continue
                            if language == 'c':
                                if variable in lq_identifiers['elf']['variables']:
                                    continue
                            all_identifiers_per_language[language]['variables'].add(variable)
                            variables.add(variable)

                        strings = sorted(strings)
                        variables = sorted(variables)
                        functions = sorted(functions)

                        num_strings = num_funcs = num_vars = 'any'

                        if len(strings) >= heuristics['strings_minimum_present']:
                            num_strings = str(int(max(len(strings)//heuristics['strings_percentage'], heuristics['strings_matched'])))

                        if len(functions) >= heuristics['functions_minimum_present']:
                            num_funcs = str(int(max(len(functions)//heuristics['functions_percentage'], heuristics['functions_matched'])))

                        if len(variables) >= heuristics['variables_minimum_present']:
                            num_vars = str(int(max(len(variables)//heuristics['variables_percentage'], heuristics['variables_matched'])))

                        if not (strings == [] and variables == [] and functions == []):
                            yara_tags = sorted(set(tags + [language]))
                            yara_file = yara_directory / (f"{metadata['archive']}-{metadata['language']}.yara")
                            rule_uuid = generate_yara(yara_file, metadata, functions, variables, strings,
                                                      yara_tags, num_strings, num_funcs, num_vars,
                                                      fullword, yara_env['operator'], bang_type)

        except Exception as e:
            continue

    # exit if there are no valid packages
    if packages == []:
        print("No packages for processing found", file=sys.stderr)
        sys.exit(1)

    fullword = ''
    if yara_env['fullword']:
        fullword = ' fullword'

    # Now generate the top level YARA file. This requires a new yara directory
    yara_directory = yara_env['yara_directory'] / 'src' / top_purl.type

    # TODO: sort the packages based on version number
    for language in languages:
        # read the JSON again, this time aggregate the data
        all_strings_intersection = set()
        all_functions_intersection = set()
        all_variables_intersection = set()

        website = ''
        cpe = ''
        cpe23 = ''

        # keep track of if the first element is being processed
        is_start = True

        for package in packages:
            with open(package, 'r') as json_archive:
                json_results = json.load(json_archive)

                if website == '':
                    website = json_results['metadata']['website']

                if cpe == '':
                    cpe = json_results['metadata']['cpe']
                if cpe23 == '':
                    cpe23 = json_results['metadata']['cpe23']

                strings = set()

                if not no_strings:
                    for string in json_results['strings']:
                        if len(string) >= yara_env['string_minimum_length'] and len(string) <= yara_env['string_maximum_length']:
                            if language == 'c':
                                if string in lq_identifiers['elf']['strings']:
                                    continue
                            strings.add(string)

                functions = set()

                if not no_functions:
                    for function in json_results['functions']:
                        if len(function) < yara_env['identifier_cutoff']:
                            continue
                        if language == 'c':
                            if function in lq_identifiers['elf']['functions']:
                                continue
                        functions.add(function)

                if not no_variables:
                    variables = set()
                    for variable in json_results['variables']:
                        if len(variable) < yara_env['identifier_cutoff']:
                            continue
                        if language == 'c':
                            if variable in lq_identifiers['elf']['variables']:
                                continue
                        variables.add(variable)

                if is_start:
                    all_strings_intersection.update(strings)
                    all_functions_intersection.update(functions)
                    all_variables_intersection.update(variables)
                    is_start = False
                else:
                    all_strings_intersection &= strings
                    all_functions_intersection &= functions
                    all_variables_intersection &= variables

        # sort the identifiers so they are printed in
        # sorted order in the YARA rule as well
        strings = sorted(all_identifiers_per_language[language]['strings'])
        variables = sorted(all_identifiers_per_language[language]['variables'])
        functions = sorted(all_identifiers_per_language[language]['functions'])

        # adapt the heuristics based on the minimum amount of strings
        # found in a package.

        # first instantiate the heuristics
        heuristics = copy.deepcopy(yara_env['heuristics'])

        # then change the percentage based on the minimum
        # amount of identifiers, and the union
        heuristics['strings_percentage'] = min(heuristics['strings_percentage'],
                                               heuristics['strings_percentage'] * min_per_language[language]['strings'] / len(strings))
        heuristics['functions_percentage'] = min(heuristics['functions_percentage'],
                                                heuristics['functions_percentage'] * min_per_language[language]['functions'] / len(functions))
        heuristics['variables_percentage'] = min(heuristics['variables_percentage'],
                                                 heuristics['variables_percentage'] * min_per_language[language]['variables'] / len(variables))

        # finally generate union and intersection files
        # that operate on all versions of a package
        archive_name = f'{top_purl.name}-union'
        metadata = {'archive': archive_name, 'name': archive_name, 'language': language,
                    'package': top_purl.name, 'packageurl': top_purl,
                    'website': website, 'cpe': cpe, 'cpe23': cpe23}

        if not (strings == [] and variables == [] and functions == []):
            num_strings = num_funcs = num_vars = 'any'

            if len(strings) >= heuristics['strings_minimum_present']:
                num_strings = str(int(max(len(strings)//heuristics['strings_percentage'], heuristics['strings_matched'])))

            if len(functions) >= heuristics['functions_minimum_present']:
                num_funcs = str(int(max(len(functions)//heuristics['functions_percentage'], heuristics['functions_matched'])))

            if len(variables) >= heuristics['variables_minimum_present']:
                num_vars = str(int(max(len(variables)//heuristics['variables_percentage'], heuristics['variables_matched'])))

            yara_file = yara_directory / (f"{metadata['archive']}-{metadata['language']}.yara")
            yara_tags = sorted(set(tags + [language]))
            rule_uuid = generate_yara(yara_file, metadata, functions, variables, strings,
                                      yara_tags, num_strings, num_funcs, num_vars,
                                      fullword, yara_env['operator'], bang_type)

        strings = sorted(all_strings_intersection)
        variables = sorted(all_variables_intersection)
        functions = sorted(all_functions_intersection)

        # reset heuristics
        heuristics = copy.deepcopy(yara_env['heuristics'])

        archive_name = f'{top_purl.name}-intersection'
        metadata = {'archive': archive_name, 'name': archive_name, 'language': language,
                    'package': top_purl.name, 'packageurl': top_purl,
                    'website': website, 'cpe': cpe, 'cpe23': cpe23}

        if not (strings == [] and variables == [] and functions == []):
            num_strings = num_funcs = num_vars = 'any'

            if len(strings) >= heuristics['strings_minimum_present']:
                num_strings = str(int(max(len(strings)//heuristics['strings_percentage'], heuristics['strings_matched'])))

            if len(functions) >= heuristics['functions_minimum_present']:
                num_funcs = str(int(max(len(functions)//heuristics['functions_percentage'], heuristics['functions_matched'])))

            if len(variables) >= heuristics['variables_minimum_present']:
                num_vars = str(int(max(len(variables)//heuristics['variables_percentage'], heuristics['variables_matched'])))

            yara_file = yara_directory / (f"{metadata['archive']}-{metadata['language']}.yara")

            yara_tags = sorted(set(tags + [language]))
            rule_uuid = generate_yara(yara_file, metadata, functions, variables, strings,
                                      yara_tags, num_strings, num_funcs, num_vars,
                                      fullword, yara_env['operator'], bang_type)


if __name__ == "__main__":
    app()
