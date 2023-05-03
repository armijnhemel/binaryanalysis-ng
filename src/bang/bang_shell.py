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
    def compose(self) -> ComposeResult:
        tree: Tree[dict] = Tree("BANG results")
        tree.root.expand()

        md_path = '/tmp/bang4/root'
        metadir = pathlib.Path(md_path)
        pretty = False

        md = MetaDirectory.from_md_path(metadir.parent, metadir.name)
        try:
            m = f'{md.file_path}'
        except MetaDirectoryException:
            print(f'directory {metadir} not found, exiting', file=sys.stderr)
            sys.exit(1)

        ## recursively build subtrees
        with md.open(open_file=False, info_write=False):
            self.build_tree(md, metadir.parent, tree.root)

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

    def on_node_tree_highlighted(self, event):
        pass
    def on_node_tree_selected(self, event):
        pass
    def on_tree_node_collapsed(self, event):
        pass

class BangShell(App):
    BINDINGS = [
        Binding(key="q", action="quit", description="Quit"),
    ]

    CSS_PATH = "bang_shell.css"

    def compose(self) -> ComposeResult:
        with Container(id='app-grid'):
            yield BangTree("BANG results")

            yield Static('Yo')
        yield Footer()


if __name__ == "__main__":
    app = BangShell()
    app.run()
