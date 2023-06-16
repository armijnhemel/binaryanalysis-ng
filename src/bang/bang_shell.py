#!/usr/bin/env python3

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

import pathlib
import sys

from typing import Any

import click

from .meta_directory import MetaDirectory, MetaDirectoryException
from . import parser_utils

from rich.console import Group, group
import rich.table

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Footer, Static, Tree
from textual.widgets.tree import TreeNode

#from textual.logging import TextualHandler

#logging.basicConfig(
    #level="NOTSET",
    #handlers=[TextualHandler()],
#)


class BangShell(App):
    BINDINGS = [
        Binding(key="q", action="quit", description="Quit"),
    ]

    CSS_PATH = "bang_shell.css"

    def __init__(self, result_directory, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.metadir = result_directory
        self.reporters = parser_utils.get_reporters()

    def compose(self) -> ComposeResult:
        self.md = MetaDirectory.from_md_path(self.metadir.parent, self.metadir.name)
        tree: Tree[dict] = Tree("BANG results")
        tree.show_root = False
        tree.root.expand()

        try:
            m = f'{self.md.file_path}'
        except MetaDirectoryException:
            print(f'directory {self.metadir} not found, exiting', file=sys.stderr)
            sys.exit(1)

        # build the tree (recursively)
        with self.md.open(open_file=False, info_write=False):
            self.build_tree(self.md, self.metadir.parent, tree.root)

        table = self.build_meta_table(self.md)
        self.static_widget = Static(Group(table, self.build_meta_report(self.md)))

        with Container(id='app-grid'):
            yield tree
            with VerticalScroll(id='result-area'):
                yield self.static_widget
        yield Footer()

    def on_tree_tree_highlighted(self, event: Tree.NodeHighlighted[None]) -> None:
        pass

    def on_tree_node_selected(self, event: Tree.NodeSelected[None]) -> None:
        '''Display the reports of a node when it is selected'''
        if event.node.data is not None:
            table = self.build_meta_table(event.node.data)
            self.static_widget.update(Group(table, self.build_meta_report(event.node.data)))
        else:
            self.static_widget.update()

    def on_tree_node_collapsed(self, event: Tree.NodeCollapsed[None]) -> None:
        pass

    def build_tree(self, md, parent, parent_node):
        node_name = pathlib.Path(md.file_path.name)
        labels = md.info.get("labels", [])

        have_subfiles = False
        files = []
        for k,v in sorted(md.info.get('extracted_files', {}).items()):
            have_subfiles = True
            files.append((k,v, 'regular'))

        for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
            have_subfiles = True
            files.append((k,v, 'regular'))

        for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
            have_subfiles = True
            files.append((k,v, 'regular'))

        for k,v in sorted(md.info.get('unpacked_symlinks', {}).items()):
            have_subfiles = True
            files.append((k,v, 'symlink'))

        for k,v in sorted(md.info.get('unpacked_hardlinks', {}).items()):
            have_subfiles = True
            files.append((k,v, 'hardlink'))

        if 'elf' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024ba'
        elif 'compressed' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024b8'
        elif 'font' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024bb'
        else:
            pretty_node_name = str(node_name)

        if have_subfiles:
            this_node = parent_node.add(pretty_node_name, data=md, expand=True)
        else:
            this_node = parent_node.add_leaf(pretty_node_name, data=md)

        # first create trees for the individual sub directories
        # which will then be used as parents.
        path_to_node = {}
        for i in sorted(files):
            # k: path, v: metadir, t: filetype
            k, v, t = i
            parent_path = pathlib.Path(*list(k.parts[:2]))
            path_name = k.relative_to(parent_path)
            for p in reversed(path_name.parents):
                if p.name == '':
                    continue
                if p in path_to_node:
                    continue
                if p.parent.name == '':
                    path_node = this_node.add(p.name, expand=True)
                else:
                    path_node = path_to_node[p.parent].add(p.name, expand=True)
                path_to_node[p] = path_node

        # recurse into sub trees
        for i in sorted(files):
            k, v, t = i
            parent_path = pathlib.Path(*list(k.parts[:2]))
            path_name = k.relative_to(parent_path)

            if t == 'regular':
                child_md = MetaDirectory.from_md_path(parent, v)
                with child_md.open(open_file=False, info_write=False):
                    if path_name.parent.name == '':
                        self.build_tree(child_md, parent, this_node)
                    else:
                        self.build_tree(child_md, parent, path_to_node[path_name.parent])
            elif t == 'symlink' or t == 'hardlink':
                if path_name.parent.name == '':
                    self.build_tree_link(k.name, v, this_node, t)
                else:
                    self.build_tree_link(k.name, v, path_to_node[path_name.parent], t)

    def build_tree_link(self, name, link_name, parent_node, link_type):
        #link_label = f'{name}  \u2192  {link_name}'
        if link_type == 'symlink':
            link_label = f'{name}  \U0001f87a  {link_name}'
        else:
            link_label = f'{name}  \U0001f87a  {link_name}   ({link_type})'
        parent_node.add_leaf(link_label)

    def build_meta_table(self, md):
        '''Construct a parser meta information table given a meta directory'''
        with md.open(open_file=False, info_write=False):
            meta_table = rich.table.Table('', '', title='Parser data', show_lines=True, show_header=False)
            meta_table.add_row('Meta directory', f'{md.md_path}')
            meta_table.add_row('Original file', f'{md.file_path}')
            parser = md.info.get("unpack_parser")
            if parser is None:
                meta_table.add_row('Parser', f'')
            else:
                meta_table.add_row('Parser', f'{parser}')
            meta_table.add_row('Labels', f'{", ".join(md.info.get("labels",[]))}')
            if md.info.get('size') is not None:
                meta_table.add_row('Parsed size', f'{md.info.get("size")}')
            if md.info.get("metadata", []) != []:
                metadata = md.info.get("metadata", [])
                if 'hashes' in metadata:
                    for h in metadata['hashes']:
                        meta_table.add_row(h, f'{metadata["hashes"][h]}')

        return meta_table

    @group()
    def build_meta_report(self, md):
        labels = md.info.get("labels", [])
        for r in self.reporters:
            for l in labels:
                if l in r.tags:
                    reporter = r()
                    title, report_results = reporter.create_report(md)
                    for rep in report_results:
                        yield rep

@click.command(short_help='Interactive BANG shell')
@click.option('--result-directory', '-r', required=True, help='BANG result directory', type=click.Path(path_type=pathlib.Path))
def main(result_directory):
    app = BangShell(result_directory)
    app.run()

if __name__ == "__main__":
    main()
