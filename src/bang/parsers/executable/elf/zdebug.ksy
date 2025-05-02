meta:
  id: zdebug
  title: GNU zdebug
  encoding: UTF-8
  endian: be
  license: CC0-1.0
  ks-version: 0.9
doc-ref: <http://www.linker-aliens.org/blogs/ali/entry/elf_section_compression/>
doc: |
  Generate test file for a simple 'Hello World':
  $ cc -g hello.c -gz=zlib-gnu
seq:
  - id: magic
    contents: 'ZLIB'
  - id: len_data   # length of uncompressed data
    type: u8
  - id: data
    size-eos: true
    process: zlib
