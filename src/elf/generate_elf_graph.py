#!/usr/bin/env python3

# This script takes a result directory from BANG, searches for the ELF files,
# records dependencies (taking symbolic links and RPATH into account) and
# generates different types of output.
#
# The method works as follows:
#
# 1. process results from BANG and store:
#    a) names of dynamically ELF files
#    b) symbols defined by the ELF files (including visibility,
#       type and binding)
#    c) symbols exported by the ELF files (including binding, type, and so on)
#    d) dependencies declared in dynamically linked files,
#       possibly indirect (symbolic links)
#
# 2. for each group of binaries (architecture, endianness, etc.) it
#    will then generate output files with all the information from 1.
#
# The typical use case would be a firmware of an embedded system that
# has been unpacked first into a separate directory.
#
# Background material about the method can be found here:
#
# https://lwn.net/Articles/548216/
# https://github.com/armijnhemel/conference-talks/tree/master/fsfe2013
#
# ELF background information can be found in public sources here:
#
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
# https://en.wikipedia.org/wiki/Weak_symbol
# https://refspecs.linuxbase.org/elf/elf.pdf
# https://android.googlesource.com/platform/art/+/master/runtime/elf.h
# https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-43405/index.html
#
# Licensed under the terms of the General Public License version 3
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions

# TODO: RPATH and RUNPATH
# TODO: colour edges for dot/graphviz

import collections
import configparser
import os
import pathlib
import pickle
import secrets
import string
import sys
import tempfile

import click
import pydot


def createtext(outputdir, binaries, linked_libraries,
                 filename_to_full_path, elf_to_exported_symbols,
                 elf_to_imported_symbols):
    '''Create a simple text output for each set of ELF files that belongs together'''
    # create a text file for each architecture/operating system
    # combination that was found.
    #
    # * file name
    # * list of dependencies
    pass

def create_dot(outputdir, binaries, linked_libraries,
               filename_to_full_path, elf_to_exported_symbols,
               elf_to_imported_symbols, hashes):
    '''Create a Graphviz dot output for each set of ELF files that belongs together'''
    for filename in binaries:
        graph = pydot.Dot(graph_type='digraph')
        root_node = pydot.Node(str(filename))
        graph.add_node(root_node)

        if linked_libraries[filename] == []:
            # standalone file, continue
            continue

        nodes_and_edges = collections.deque()

        nodes_and_edges.append((root_node, filename))

        processed_nodes = set([filename])

        while True:
            try:
                node, node_name = nodes_and_edges.popleft()
                if node_name not in linked_libraries:
                    continue

                # record the dependencies that are linked
                for l in linked_libraries[node_name]:
                    libfound = False
                    if l in filename_to_full_path:
                        for fl in filename_to_full_path[l]:
                            # only record dependencies that
                            # are in the same collection of of binaries
                            if fl in binaries:
                                libfound = True
                                break
                    if not libfound:
                        # problem here, ignore for now
                        continue
                    lib_node = pydot.Node(str(fl))
                    graph.add_node(lib_node)
                    graph.add_edge(pydot.Edge(node, lib_node))
                    if fl not in processed_nodes:
                        nodes_and_edges.append((lib_node, fl))
                        processed_nodes.add(fl)
            except Exception as e:
                break

        graph_filename_png = f"{filename.name}-{hashes[filename]}.png"
        graph_filename_svg = f"{filename.name}-{hashes[filename]}.svg"

        # write graph as PNG and SVG
        graph.write_png(outputdir / graph_filename_png)
        graph.write_svg(outputdir / graph_filename_svg)



def createcypher(outputdir, binaries, linked_libraries,
                 filename_to_full_path, elf_to_exported_symbols,
                 elf_to_imported_symbols):
    '''Create a Cypher file for each set of ELF files that belongs together'''

    # create a cypher file for a collection of binaries. This means:
    #
    # * generating (random) names for the nodes in the graph
    # * defining vertices between the nodes
    # * writing the output file
    elf_to_placeholder = {}
    placeholder_to_elf = {}
    symbol_to_placeholder = {}
    placeholder_to_symbol = {}
    all_placeholder_names = set()

    for filename in binaries:
        # Create a placeholder name and check if it already exists. If so
        # generate and check a new name until one is found that doesn't exist.
        #
        # Taken from the Python3 documentation:
        # https://docs.python.org/3/library/secrets.html#recipes-and-best-practices
        while True:
            placeholdername = ''.join(secrets.choice(string.ascii_letters) for i in range(8))
            if placeholdername not in placeholder_to_elf and placeholdername not in all_placeholder_names:
                placeholder_to_elf[placeholdername] = filename
                break
        elf_to_placeholder[filename] = placeholdername
        all_placeholder_names.add(placeholdername)

    # write the data to a Cypher file
    cypherfile = tempfile.mkstemp(dir=outputdir, suffix='.cypher')
    os.fdopen(cypherfile[0]).close()
    with open(cypherfile[1], 'w') as cypherfileopen:
        cypherfileopen.write("CREATE ")

        # first add all the ELF files as nodes to the graph
        seen_first_node = False
        for filename in binaries:

            # some magic to make sure that nodes are formatted
            # correctly in the file, else Neo4J will complain
            # about malformed Cypher.
            if seen_first_node:
                cypherfileopen.write(", \n")
            else:
                seen_first_node = True

            # define a node
            cypherfileopen.write("(%s:ELF {name: '%s'})" % (elf_to_placeholder[filename], filename))

        # add links between files
        for filename in binaries:
            if linked_libraries[filename] == []:
                continue

            # record the dependencies that are linked
            for l in linked_libraries[filename]:
                libfound = False
                if l in filename_to_full_path:
                    for fl in filename_to_full_path[l]:
                        # only record dependencies that
                        # are in the same collection of of binaries
                        if fl in binaries:
                            libfound = True
                            break
                if not libfound:
                    # problem here, ignore for now
                    continue

                cypherfileopen.write(", \n")
                cypherfileopen.write("(%s)-[:LINKSWITH]->(%s)" % (elf_to_placeholder[filename], elf_to_placeholder[fl]))

        # then add all the exported symbols just once
        tmpexportsymbols = set()

        for filename in binaries:
            for exp in elf_to_exported_symbols[filename]:
                # remove a few symbols that are not needed
                if exp['size'] == 0:
                    continue
                if exp['type'] == 'NOTYPE':
                    continue
                tmpexportsymbols.add((exp['name'], exp['type'], exp['binding']))

        for exp in tmpexportsymbols:
            (symbolname, symboltype, symbolbinding) = exp
            while True:
                placeholdername = ''.join(secrets.choice(string.ascii_letters) for i in range(8))
                if placeholdername not in placeholder_to_symbol and placeholdername not in all_placeholder_names:
                    placeholder_to_symbol[placeholdername] = symbolname
                    break
            symbol_to_placeholder[(symbolname, symboltype)] = placeholdername
            all_placeholder_names.add(placeholdername)
            cypherfileopen.write(", \n")
            cypherfileopen.write("(%s:SYMBOL {name: '%s', type: '%s'})" % (symbol_to_placeholder[(symbolname, symboltype)], symbolname, symboltype))

        # then declare for all the symbols which are exported
        for filename in binaries:
            for exp in elf_to_exported_symbols[filename]:
                # remove a few symbols that are not needed
                if exp['size'] == 0:
                    continue
                if exp['type'] == 'no_type':
                    continue
                cypherfileopen.write(", \n")
                cypherfileopen.write("(%s)-[:EXPORTS]->(%s)" % (elf_to_placeholder[filename], symbol_to_placeholder[(exp['name'], exp['type'])]))

        # store which files use which symbols
        for filename in binaries:
            for imp in elf_to_imported_symbols[filename]:
                if imp['size'] == 0:
                    continue
                if imp['binding'] == 'local':
                    # skip LOCAL symbols
                    continue
                if imp['binding'] == 'weak':
                    # skip WEAK symbols for now
                    continue
                if (imp['name'], imp['type']) in symbol_to_placeholder:
                    cypherfileopen.write(", \n")
                    cypherfileopen.write("(%s)-[:USES]->(%s)" % (elf_to_placeholder[filename], symbol_to_placeholder[(imp['name'], imp['type'])]))
                else:
                    # something is horribly wrong here
                    pass


@click.command(short_help='process BANG result files and output ELF graphs')
@click.option('--config-file', '-c', required=True, help='configuration file',
              type=click.File('r'))
@click.option('--directory', '-d', 'result_directory', required=True,
              help='BANG result directory', type=click.Path(exists=True))
@click.option('--output', '-o', help='output format')
def main(config_file, result_directory, output):

    bang_result_directory = pathlib.Path(result_directory)

    if not bang_result_directory.is_dir():
        print("%s is not a directory" % bang_result_directory, file=sys.stderr)
        sys.exit(1)

    #supported_formats = ['text', 'cypher', 'graphviz']
    supported_formats = ['cypher', 'dot']

    # check the output format. By default it is cypher.
    outputformat = 'cypher'
    if output is not None:
        if output not in supported_formats:
            print(f"Unsupported output format {output}", file=sys.stderr)
            sys.exit(1)
        outputformat = output

    config = configparser.ConfigParser()

    try:
        config.read_file(config_file)
    except Exception:
        print("Cannot read configuration file", file=sys.stderr)
        sys.exit(1)

    # process the configuration file and store settings
    config_settings = {}

    outputdir = None
    for section in config.sections():
        if outputformat == 'dot':
            if section == 'dot':
                try:
                    outputdir = pathlib.Path(config.get(section, 'outputdir'))
                except:
                    print("Directory to write graphviz files not configured",
                          file=sys.stderr)
                    config_file.close()
                    sys.exit(1)
                if not outputdir.exists():
                    print("Directory to write graphviz files does not exist",
                          file=sys.stderr)
                    config_file.close()
                    sys.exit(1)
                if not outputdir.is_dir():
                    print("Directory to write graphviz files is not a directory",
                          file=sys.stderr)
                    config_file.close()
                    sys.exit(1)
        if outputformat == 'cypher':
            if section == 'cypher':
                try:
                    outputdir = pathlib.Path(config.get(section, 'outputdir'))
                except:
                    print("Directory to write Cypher files not configured",
                          file=sys.stderr)
                    config_file.close()
                    sys.exit(1)
                if not outputdir.exists():
                    print("Directory to write Cypher files does not exist",
                          file=sys.stderr)
                    config_file.close()
                    sys.exit(1)
                if not outputdir.is_dir():
                    print("Directory to write Cypher files is not a directory",
                          file=sys.stderr)
                    config_file.close()
                    sys.exit(1)
    config_file.close()

    if outputformat == 'cypher':
        if outputdir is None:
            print("Directory to write output files to not configured",
                  file=sys.stderr)
            sys.exit(1)

    # open the top level pickle
    bang_pickle = bang_result_directory / 'info.pkl'
    if not bang_pickle.exists():
        print("result pickle not found, exiting", file=sys.stderr)
        sys.exit(1)

    try:
        bang_data = pickle.load(open(bang_pickle, 'rb'))
    except:
        print("Could not read BANG results pickle",
              file=sys.stderr)
        sys.exit(1)

    # Keep track of architecture/ABI/endianness/etc. for each ELF file
    #
    # Programs that are linked should at least have the same:
    #
    # * endianness
    # * bit size
    # * ABI
    #
    # and generally also the same architecture, although there
    # are cases where instead the architecture family (ARM) should
    # be looked at.
    #
    # Typically there will only be files of one architecture (family)
    # in a firmware but sometimes there are files of an incompatible
    # architecture that obviously should be avoided (you cannot link
    # MIPS binaries with ARM binaries for example)
    #
    # Example of data stored:
    # {'endian': 'big', 'machine': 'mips', 'bits': 32, 'abi': 'system_v'}
    binary_to_machine = {}

    # Record the symbols and linked libraries found in each ELF binary:
    #
    # * imported symbols (UND in readelf)
    # * exported ones will be in 'exports'
    # * libraries needed during linking
    elf_to_imported_symbols = {}
    elf_to_exported_symbols = {}
    linked_libraries = {}

    # store names to full paths
    filename_to_full_path = {}

    # store symbolic links to their final target
    symlink_to_target = {}

    file_to_parent = {}

    hashes = {}

    # create the file deque to store new nodes
    file_deque = collections.deque()
    file_deque.append(bang_pickle)

    is_root = True

    # walk the unpack tree recursively
    while True:
        try:
            orig_file_pickle = file_deque.popleft()
        except:
            break

        try:
            bang_data = pickle.load(open(orig_file_pickle, 'rb'))
        except:
            continue

        if not is_root:
            if 'labels' in bang_data:
                path_name = orig_file_pickle.with_name('pathname')
                if not path_name.exists():
                    print("pathname file not found, exiting", file=sys.stderr)
                    sys.exit(1)

                try:
                    with open(path_name, 'r') as path_name_file:
                        binary_name = pathlib.Path(path_name_file.read())
                        if not binary_name.is_absolute():
                            binary_name = pathlib.Path('/').joinpath(*list(binary_name.parts[2:]))
                        else:
                            binary_name = binary_name.name
                except Exception as e:
                    print("Could not process pathname file", e,
                          file=sys.stderr)
                    continue


                # only consider dynamically linked ELF files
                if 'elf' in bang_data['labels'] and 'dynamic' in bang_data['metadata']['elf_type']:
                    print(binary_name, path_name)
                    #print(bang_data['labels'])

        is_root = False

        # store symbolic links and hard links
        if 'unpacked_symlinks' in bang_data:
            for s in bang_data['unpacked_symlinks']:
                orig = pathlib.Path('/').joinpath(*list(s.parts[2:]))
                target = bang_data['unpacked_symlinks'][s]
                symlink_to_target[orig] = target
        elif 'unpacked_hardlinks' in bang_data:
            print(bang_data['unpacked_hardlinks'])

        # add the unpacked/extracted files to the queue
        if 'unpacked_relative_files' in bang_data:
            for unpacked_file in bang_data['unpacked_relative_files']:
                file_meta_directory = bang_data['unpacked_relative_files'][unpacked_file]
                file_pickle = bang_result_directory.parent / file_meta_directory / 'info.pkl'
                child_node_name = str(unpacked_file)
                file_deque.append(file_pickle)

        if 'unpacked_absolute_files' in bang_data:
            for unpacked_file in bang_data['unpacked_absolute_files']:
                file_meta_directory = bang_data['unpacked_absolute_files'][unpacked_file]
                file_pickle = bang_result_directory.parent / file_meta_directory / 'info.pkl'
                child_node_name = str(unpacked_file)
                file_deque.append(file_pickle)

        if 'extracted_files' in bang_data:
            for unpacked_file in bang_data['extracted_files']:
                file_meta_directory = bang_data['extracted_files'][unpacked_file]
                file_pickle = bang_result_directory.parent / file_meta_directory / 'info.pkl'
                child_node_name = str(unpacked_file)
                file_deque.append(file_pickle)

    for bang_result in bang_results['scantree']:

        # store machine specific information
        machine_info = {'endian': result['metadata']['endian'],
                        'machine': result['metadata']['machine_name'],
                        'bits': result['metadata']['bits'],
                        'abi': result['metadata']['abi_name']}
        binary_to_machine[binary_name] = machine_info

        # store the dependencies
        linked_libraries[binary_name] = result['metadata']['needed']

        # store the symbols from the dynamic symbol table
        elf_to_imported_symbols[binary_name] = []
        elf_to_exported_symbols[binary_name] = []
        for s in result['metadata']['dynamic_symbols']:
            # ignore everything but functions and variables
            if s['type'] not in ['func', 'object']:
                continue
            # ignore symbols that have a local binding, only
            # look at global and weak symbols
            if s['binding'] == 'local':
                continue
            # ignore ABS section
            if s['section_index'] == 0xfff1:
                continue
            if s['section_index'] == 0:
                if not s in elf_to_imported_symbols[binary_name]:
                    elf_to_imported_symbols[binary_name].append(s)
            else:
                # TODO: this isn't quite correct, as it also includes
                # symbols from for example ABS
                if not s in elf_to_exported_symbols[binary_name]:
                    elf_to_exported_symbols[binary_name].append(s)

        # store the symbols from the symbol table (if any)
        for s in result['metadata']['symbols']:
            # ignore everything but functions and variables
            if s['type'] not in ['func', 'object']:
                continue
            # ignore symbols that have a local binding, only
            # look at global and weak symbols
            if s['binding'] == 'local':
                continue
            # ignore ABS section
            if s['section_index'] == 0xfff1:
                continue

            if s['section_index'] == 0:
                if not s in elf_to_imported_symbols[binary_name]:
                    elf_to_imported_symbols[binary_name].append(s)
            else:
                # TODO: this isn't quite correct, as it also includes
                # symbols from for example ABS
                if not s in elf_to_exported_symbols[binary_name]:
                    elf_to_exported_symbols[binary_name].append(s)
    if 'symbolic link' in bang_results['scantree'][bang_result]['labels']:
        # It could be that a name of a dependency in an ELF file
        # is the name of a symbolic link, instead of the actual
        # ELF file. This is why we also need to (recursively)
        # look at symbolic links and store the target.
        symlink_to_target[binary_name] = str(bang_results['scantree'][bang_result]['target'])
        parent = bang_results['scantree'][bang_result]['parent']
        file_to_parent[binary_name] = parent

    # split the files into separate sets (per abi, endian, etc.)
    file_sets = {}

    for binary in binary_to_machine:
        abi = binary_to_machine[binary]['abi']
        if abi not in file_sets:
            file_sets[abi] = {}

        endian = binary_to_machine[binary]['endian']
        if endian not in file_sets[abi]:
            file_sets[abi][endian] = {}

        bits = binary_to_machine[binary]['bits']
        if bits not in file_sets[abi][endian]:
            file_sets[abi][endian][bits] = {}

        machine = binary_to_machine[binary]['machine']
        if machine not in file_sets[abi][endian][bits]:
            file_sets[abi][endian][bits][machine] = []
        file_sets[abi][endian][bits][machine].append(binary)

    for f in file_sets:
        for e in file_sets[f]:
            for b in file_sets[f][e]:
                for m in file_sets[f][e][b]:
                    binaries = file_sets[f][e][b][m]

                    # now generate output
                    if outputformat == 'cypher':
                        createcypher(outputdir, binaries, linked_libraries,
                                     filename_to_full_path, elf_to_exported_symbols,
                                     elf_to_imported_symbols)
                    elif outputformat == 'dot':
                        create_dot(outputdir, binaries, linked_libraries,
                                   filename_to_full_path, elf_to_exported_symbols,
                                   elf_to_imported_symbols, hashes)

if __name__ == "__main__":
    main()
