#!/usr/bin/env python3

# This script takes a result file from BANG and generates a visual
# representation of the contents
#
# Licensed under the terms of the General Public License version 3
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright - Armijn Hemel, Tjaldur Software Governance Solutions

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


@click.command(short_help='process BANG result files and output graphviz files')
@click.option('--config-file', '-c', required=True, help='configuration file',
              type=click.File('r'))
@click.option('--directory', '-d', 'result_directory', required=True,
              help='BANG result directory', type=click.Path(exists=True))
def main(config_file, result_directory):

    bang_result_directory = pathlib.Path(result_directory)

    if not bang_result_directory.is_dir():
        print("%s is not a directory" % bang_result_directory, file=sys.stderr)
        sys.exit(1)

    # output formats, currently hardcoded to dot
    supported_formats = ['dot']

    # check the output format. By default it is dot.
    outputformat = 'dot'

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

    # open the top level pathname
    path_name = bang_result_directory / 'pathname'
    if not path_name.exists():
        print("pathname file not found, exiting", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path_name, 'r') as path_name_file:
            root_name = pathlib.Path(path_name_file.read()).name
    except:
        print("Could not process pathname file",
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

    # initialize the graph
    graph = pydot.Dot(graph_type='digraph', showboxes=True)

    # initialize the root node
    is_root = True
    label = ''
    group = ''

    # create the file deque to store new nodes
    file_deque = collections.deque()
    file_deque.append((bang_pickle, root_name, None, label, group, is_root))

    # walk the unpack tree recursively
    while True:
        try:
            orig_file_pickle, node_name, parent_node, label, group, is_root = file_deque.popleft()
        except:
            break

        try:
            bang_data = pickle.load(open(orig_file_pickle, 'rb'))
        except:
            continue

        # create the node and add to the graph
        bang_node = pydot.Node(node_name)
        graph.add_node(bang_node)

        # if this node is not the root node create an edge between
        # the parent node and the new node
        if not is_root:
            graph.add_edge(pydot.Edge(parent_node, bang_node, label=label, group=group))

        is_root = False

        # add the unpacked/extracted files to the queue
        if 'unpacked_relative_files' in bang_data:
            for unpacked_file in bang_data['unpacked_relative_files']:
                file_meta_directory = bang_data['unpacked_relative_files'][unpacked_file]
                file_pickle = bang_result_directory.parent / file_meta_directory / 'info.pkl'
                child_node_name = str(unpacked_file)
                group = str(unpacked_file.parents[-2])
                file_deque.append((file_pickle, child_node_name, bang_node, 'unpack', group, is_root))

        if 'unpacked_absolute_files' in bang_data:
            for unpacked_file in bang_data['unpacked_absolute_files']:
                file_meta_directory = bang_data['unpacked_absolute_files'][unpacked_file]
                file_pickle = bang_result_directory.parent / file_meta_directory / 'info.pkl'
                child_node_name = str(unpacked_file)
                group = str(unpacked_file.parents[-2])
                file_deque.append((file_pickle, child_node_name, bang_node, 'unpack', group, is_root))

        if 'extracted_files' in bang_data:
            for unpacked_file in bang_data['extracted_files']:
                file_meta_directory = bang_data['extracted_files'][unpacked_file]
                file_pickle = bang_result_directory.parent / file_meta_directory / 'info.pkl'
                child_node_name = str(unpacked_file)
                group = str(unpacked_file.parents[-2])
                file_deque.append((file_pickle, child_node_name, bang_node, 'extract', group, is_root))

    graph_filename_png = f"{root_name}.png"
    graph_filename_svg = f"{root_name}.svg"

    # write graph as PNG and SVG to the output directory
    graph.write_png(outputdir / graph_filename_png)
    graph.write_svg(outputdir / graph_filename_svg)

if __name__ == "__main__":
    main()
