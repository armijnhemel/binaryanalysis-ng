meta:
  id: elf_arm_attributes
  title: Executable and Linkable Format ARM attributes
  application: SVR4 ABI and up, many *nix systems
  xref:
    justsolve: Executable_and_Linkable_Format
    mime:
      - application/x-elf
      - application/x-coredump
      - application/x-executable
      - application/x-object
      - application/x-sharedlib
    pronom:
      - fmt/688 # 32bit Little Endian
      - fmt/689 # 32bit Big Endian
      - fmt/690 # 64bit Little Endian
      - fmt/691 # 64bit Big Endian
    wikidata: Q1343830
  tags:
    - executable
    - linux
  endian: le
  license: CC0-1.0
  ks-version: 0.9
seq:
  - id: version
    type: u1
  - id: sections
    type: arm_attributes_section_entry
    repeat: eos
    doc-ref: https://developer.arm.com/documentation/ihi0044/h/?lang=en
types:
  arm_attributes_section_entry:
    seq:
      - id: len_section
        type: u4
      - id: rest_of_entry
        type: arm_attributes_section_entry_rest
        size: len_section - len_section._sizeof
  arm_attributes_section_entry_rest:
    seq:
      - id: vendor_name
        type: strz
        encoding: ASCII
      - id: attribute_tags
        size-eos: true
