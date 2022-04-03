meta:
  id: crx
  title: Chrome Extensions
  license: CC0-1.0
  ks-version: 0.9
  imports:
    - zip
  encoding: utf-8
  endian: le
doc-ref:
  - https://chromium.googlesource.com/chromium/src.git/+/62.0.3178.1/chrome/common/extensions/docs/templates/articles/crx.html
  - https://pypi.org/project/crx-unpack/
seq:
  - id: header
    type: header
  - id: zip
    type: zip
types:
  header:
    seq:
      - id: magic
        contents: 'Cr24'
      - id: version
        type: u4
        valid: 2
        # only support v2 now
      - id: len_public_key
        type: u4
      - id: len_signature
        type: u4
      - id: public_key
        size: len_public_key
      - id: signature
        size: len_signature
    instances:
      len_header:
        value: magic._sizeof + version._sizeof + len_public_key._sizeof + len_signature._sizeof + len_public_key + len_signature
