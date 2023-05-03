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

import click
import pathlib
import sys

from typing import Any

from .meta_directory import MetaDirectory, MetaDirectoryException

import rich.table

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.widgets import Footer, Static, Tree
from textual.widgets.tree import TreeNode

#from textual.logging import TextualHandler

#logging.basicConfig(
    #level="NOTSET",
    #handlers=[TextualHandler()],
#)

class BangTree(Tree):
    def __init__(self, metadir, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.metadir = metadir

    def compose(self) -> ComposeResult:
        self.md = MetaDirectory.from_md_path(self.metadir.parent, self.metadir.name)
        tree: Tree[dict] = Tree("BANG results")
        tree.root.expand()

        try:
            m = f'{self.md.file_path}'
        except MetaDirectoryException:
            print(f'directory {self.metadir} not found, exiting', file=sys.stderr)
            sys.exit(1)

        ## recursively build subtrees
        with self.md.open(open_file=False, info_write=False):
            self.build_tree(self.md, self.metadir.parent, tree.root)

        yield tree

    def build_tree(self, md, parent, parent_node):
        node_name = pathlib.Path('/').joinpath(*list(md.file_path.parts[2:]))

        have_subfiles = False
        files = []
        for k,v in sorted(md.info.get('extracted_files', {}).items()):
            have_subfiles = True
            files.append((k,v))

        for k,v in sorted(md.info.get('unpacked_absolute_files', {}).items()):
            have_subfiles = True
            files.append((k,v))

        for k,v in sorted(md.info.get('unpacked_relative_files', {}).items()):
            have_subfiles = True
            files.append((k,v))

        # TODO: also add symbolic links and hardlinks
        for k,v in sorted(md.info.get('unpacked_symlinks', {}).items()):
            have_subfiles = True
            link_pp_path = k
            #link_label = f'{link_pp_path}  \u2192  {v}'
            link_label = f'{link_pp_path}  \U0001f87a  {v}'

        if have_subfiles:
            this_node = parent_node.add(str(node_name), data=md, expand=True)
        else:
            this_node = parent_node.add_leaf(str(node_name), data=md)

        for i in sorted(files):
            k,v = i
            child_md = MetaDirectory.from_md_path(parent, v)
            with child_md.open(open_file=False, info_write=False):
                self.build_tree(child_md, parent, this_node)

    def build_meta_table(self, md):
        '''Construct a parser meta information table given a meta directory'''
        with md.open(open_file=False, info_write=False):
            meta_table = rich.table.Table('', '', title='Parser data', show_lines=True, show_header=False)
            meta_table.add_row('Meta directory', f'{md.md_path}')
            meta_table.add_row('Original file', f'{md.file_path}')
            meta_table.add_row('Parser', f'{md.info.get("unpack_parser")}')
            meta_table.add_row('Labels', f'{", ".join(md.info.get("labels",[]))}')
            if md.info.get('size') is not None:
                meta_table.add_row('Parsed size', f'{md.info.get("size")}')
            if md.info.get("metadata", []) != []:
                metadata = md.info.get("metadata", [])
                if 'hashes' in metadata:
                    for h in metadata['hashes']:
                        meta_table.add_row(h, f'{metadata["hashes"][h]}')

        return meta_table

    def on_node_tree_highlighted(self, event: Tree.NodeHighlighted[None]) -> None:
        pass
    def on_node_tree_selected(self, event: Tree.NodeSelected[None]) -> None:
        pass
    def on_tree_node_collapsed(self, event: Tree.NodeCollapsed[None]) -> None:
        pass

class BangShell(App):
    BINDINGS = [
        Binding(key="q", action="quit", description="Quit"),
    ]

    CSS_PATH = "bang_shell.css"

    def __init__(self, result_directory, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.md = result_directory

    def compose(self) -> ComposeResult:
        bangtree = BangTree(self.md, "BANG results")

        with Container(id='app-grid'):
            yield bangtree

            yield Static(str(self.md))
        yield Footer()


@click.command(short_help='Interactive BANG shell')
@click.option('--result-directory', '-r', required=True, help='BANG result directory', type=click.Path(path_type=pathlib.Path))
def main(result_directory):
    app = BangShell(result_directory)
    app.run()

if __name__ == "__main__":
    main()
