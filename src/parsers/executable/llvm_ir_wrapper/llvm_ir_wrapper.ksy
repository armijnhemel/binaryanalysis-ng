meta:
  id: llvm_ir_wrapper
  title: LLVM IR bitcode wrapper
  file-extension: bc
  license: CC0-1.0
  endian: le
doc-ref: https://llvm.org/docs/BitCodeFormat.html
seq:
  - id: magic
    contents: [0xde, 0xc0, 0x17, 0x0b]
  - id: version
    type: u4
    valid: 0
  - id: ofs_bytecode
    type: u4
  - id: len_bytecode
    type: u4
  - id: cpu_type
    type: u4
instances:
  bytecode:
    pos: ofs_bytecode
    size: len_bytecode
