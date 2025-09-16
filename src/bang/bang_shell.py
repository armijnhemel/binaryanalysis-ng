#!/usr/bin/env python3

# Binary Analysis Next Generation (BANG!)
#
# This file is part of BANG.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only

import pathlib
import shlex
import sys

from typing import Any, Iterable

import click

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.suggester import Suggester
from textual.validation import ValidationResult, Validator
from textual.widgets import Footer, Markdown, Tree, TabbedContent, TabPane, Input, Header, DataTable

from .meta_directory import MetaDirectory, MetaDirectoryException
from . import parser_utils

class FilterValidator(Validator):
    '''Syntax validator for the filtering language.'''

    def __init__(self, **kwargs):
        # Known values: only these will be regarded as valid.
        self.labels = kwargs.get('labels', set())

    def validate(self, value: str) -> ValidationResult:
        try:
            # split the value into tokens
            tokens = shlex.split(value.lower())
            if not tokens:
                return self.failure("Empty string")

            # verify each token
            for t in tokens:
                if '=' not in t:
                    return self.failure("Invalid identifier")
                token_identifier, token_value = t.split('=', maxsplit=1)

            return self.success()
        except ValueError:
            return self.failure('Incomplete')


class BangShell(App):
    BINDINGS = [
        Binding(key="ctrl+q", key_display='ctrl-q', action="quit", description="Quit"),
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

        # build the tree (recursively)
        with self.md.open(open_file=False, info_write=False):
            self.build_tree(self.md, self.metadir.parent, tree.root)

        # create the widgets for the individual panes
        self.parser_data_table = Markdown()
        meta_markdown = self.build_meta_table(self.md)
        self.parser_data_table.update(meta_markdown)

        self.meta_report = self.build_meta_report(self.md)
        self.static_widget = Markdown('')

        tree_filter = Input(placeholder='Filter', validators=[FilterValidator()], valid_empty=True)

        with Container(id='app-grid'):
            with Container(id='left-grid'):
                yield tree_filter
                yield tree
            with TabbedContent():
                with TabPane('Parser data'):
                    with VerticalScroll():
                        yield self.parser_data_table
                with TabPane('Meta data'):
                    with VerticalScroll():
                        yield self.static_widget
        yield Footer()

    @on(Input.Submitted)
    def process_filter(self, event: Input.Submitted) -> None:
        '''Process the filter, create new tree'''
        refresh = False

        if event.validation_result is None:
            refresh = True

    def on_tree_tree_highlighted(self, event: Tree.NodeHighlighted[None]) -> None:
        pass

    def on_tree_node_selected(self, event: Tree.NodeSelected[None]) -> None:
        '''Display the reports of a node when it is selected'''
        if event.node.data is not None:
            _, event_node_data = event.node.data
            table = self.build_meta_table(event_node_data)
            self.parser_data_table.update(table)
            meta_report = self.build_meta_report(event_node_data)
            self.static_widget.update(meta_report)
        else:
            self.parser_data_table.update('')
            self.static_widget.update('')

    def on_tree_node_collapsed(self, event: Tree.NodeCollapsed[None]) -> None:
        pass

    def build_tree(self, md, parent, parent_node):
        node_name = pathlib.Path(md.file_path.name)
        labels = md.info.get("labels", [])

        have_subfiles = False
        files = []
        for k, v in sorted(md.info.get('extracted_files', {}).items()):
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
            metadata = md.info.get('metadata', {})
            if 'elf_type' in metadata:
                if 'Linux kernel module' in metadata['elf_type']:
                    pretty_node_name += ' :penguin:'
        elif 'compressed' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024b8'
        elif 'font' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024bb'
        elif 'filesystem' in labels:
            pretty_node_name = f'{str(node_name)}  :computer_disk:'
        elif 'graphics' in labels:
            pretty_node_name = f'{str(node_name)}  :framed_picture:'
        elif 'linux kernel configuration' in labels:
            pretty_node_name = f'{str(node_name)}  :penguin:'
        elif 'padding' in labels:
            pretty_node_name = f'{str(node_name)}  \U000024c5'
        elif labels:
            pretty_node_name = f'{str(node_name)}  \U0001F3F7'
        else:
            pretty_node_name = str(node_name)

        if have_subfiles:
            this_node = parent_node.add(pretty_node_name, data=(labels, md), expand=True)
        else:
            this_node = parent_node.add_leaf(pretty_node_name, data=(labels, md))

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

    def build_meta_report(self, md):
        labels = md.info.get("labels", [])
        markdown = ''
        for r in self.reporters:
            for l in labels:
                if l in r.tags:
                    reporter = r()
                    #_, report_results = reporter.create_report(md)
                    markdown += reporter.create_report(md)
        return markdown

@click.command(short_help='Interactive BANG shell')
@click.option('--result-directory', '-r', required=True, help='BANG result directory',
              type=click.Path(path_type=pathlib.Path))
def main(result_directory):
    md = MetaDirectory.from_md_path(result_directory.parent, result_directory.name)
    try:
        f'{md.file_path}'
    except MetaDirectoryException:
        print(f'Directory {result_directory} is not a valid BANG result directory, exiting',
               file=sys.stderr)
        sys.exit(1)

    app = BangShell(result_directory)
    app.run()

if __name__ == "__main__":
    main()
