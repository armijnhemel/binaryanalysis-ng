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

from rich.console import Group, group
import rich.table

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.suggester import Suggester
from textual.validation import ValidationResult, Validator
from textual.widgets import Footer, Markdown, Static, Tree, TabbedContent, TabPane, Input, Header, DataTable

from .meta_directory import MetaDirectory, MetaDirectoryException
from . import parser_utils


#from textual.logging import TextualHandler

#logging.basicConfig(
    #level="NOTSET",
    #handlers=[TextualHandler()],
#)


class BangShell(App):
    BINDINGS = [
        Binding(key="ctrl+q", action="quit", description="Quit"),
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

        # create the widgets for the individuale panes
        self.parser_data_table = Markdown()
        meta_markdown = self.build_meta_table(self.md)
        self.parser_data_table.update(meta_markdown)

        self.meta_report = self.build_meta_report(self.md)
        self.static_widget = Static(self.meta_report)

        with Container(id='app-grid'):
            yield tree
            with TabbedContent():
                with TabPane('Parser data'):
                    with VerticalScroll():
                        yield self.parser_data_table
                with TabPane('Meta data'):
                    with VerticalScroll():
                        yield self.static_widget
        yield Footer()

    def on_tree_tree_highlighted(self, event: Tree.NodeHighlighted[None]) -> None:
        pass

    def on_tree_node_selected(self, event: Tree.NodeSelected[None]) -> None:
        '''Display the reports of a node when it is selected'''
        if event.node.data is not None:
            table = self.build_meta_table(event.node.data)
            self.parser_data_table.update(table)
            meta_report = self.build_meta_report(event.node.data)
            self.static_widget.update(meta_report)
        else:
            self.parser_data_table.update('')
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
        elif 'graphics' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024bc'
        elif 'padding' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024c5'
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
            elif t in ['symlink', 'hardlink']:
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
        new_markdown = ""
        with md.open(open_file=False, info_write=False):
            new_markdown = "| | |\n|--|--|\n"
            new_markdown += f"|**Meta directory** | {md.md_path}\n"
            new_markdown += f"|**Original file** | {md.file_path}\n"
            parser = md.info.get("unpack_parser")
            if parser is None:
                new_markdown += "|**Parser** |\n"
            else:
                new_markdown += f"|**Parser** |{parser}\n"

            labels = ", ".join(md.info.get("labels", []))
            new_markdown += f"|**Labels** | {labels}\n"

            if md.info.get('size') is not None:
                new_markdown += f"|**Parsed size** | {md.info.get('size')}\n"
            if md.info.get("metadata", []) != []:
                metadata = md.info.get("metadata", [])
                if 'hashes' in metadata:
                    for h in metadata['hashes']:
                        new_markdown += f"|**{h.upper()}** | {metadata['hashes'][h]}\n"

        return new_markdown

    @group()
    def build_meta_report(self, md):
        labels = md.info.get("labels", [])
        for r in self.reporters:
            for l in labels:
                if l in r.tags:
                    reporter = r()
                    _, report_results = reporter.create_report(md)
                    for rep in report_results:
                        yield rep

@click.command(short_help='Interactive BANG shell')
@click.option('--result-directory', '-r', required=True, help='BANG result directory',
              type=click.Path(path_type=pathlib.Path))
def main(result_directory):
    app = BangShell(result_directory)
    app.run()

if __name__ == "__main__":
    main()
