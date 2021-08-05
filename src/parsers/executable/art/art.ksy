meta:
  id: art
  title: ART
  file-extension: art
  license: Apache-2.0
  ks-version: 0.9
  endian: le
  encoding: UTF-8
doc: |
  ART
doc-ref:
  - https://android.googlesource.com/platform/art/+/master/runtime/image.cc
  - https://android.googlesource.com/platform/art/+/master/runtime/image.h
seq:
  - id: magic
    contents: "art\n"
  - id: version
    type: strz
    size: 4
  - id: header
    type:
      switch-on: version
      cases:
        '"056"': header_056
types:
  header_056:
    seq:
      - id: image_begin
        type: u4
        doc: Required base address for mapping the image.
      - id: image_size
        type: u4
        doc: Image size, not page aligned.
      - id: oat_checksum
        type: u4
        doc: Checksum of the oat file we link to for load time sanity check.
      - id: oat_file_begin
        type: u4
        doc: Start address for oat file. Will be before oat_data_begin_ for .so files.
      - id: oat_data_begin
        type: u4
        doc: Required oat address expected by image Method::GetCode() pointers.
      - id: oat_data_end
        type: u4
        doc: End of oat data address range for this image file.
      - id: oat_file_end
        type: u4
        doc: |
          End of oat file address range. will be after oat_data_end_ for
          .so files. Used for positioning a following alloc spaces.
      - id: boot_image_begin
        type: u4
        doc: Boot image begin (app image headers only).
      - id: boot_image_size
        type: u4
        doc: Boot image end (app image headers only).
      - id:  boot_oat_begin
        type: u4
        doc: Boot oat begin (app image headers only).
      - id:  boot_oat_size
        type: u4
        doc: Boot oat end (app image headers only).
      - id: patch_delta
        type: u4
        doc: The total delta that this image has been patched.
      - id: image_roots
        type: u4
        doc: Absolute address of an Object[] of objects needed to reinitialize from an image.
      - id: pointer_size
        type: u4
        doc: Pointer size, this affects the size of the ArtMethods.
      - id: compile_pic
        type: u4
        valid:
          any-of: [0, 1]
        doc: Boolean (0 or 1) to denote if the image was compiled with --compile-pic option
