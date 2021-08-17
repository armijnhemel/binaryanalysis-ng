meta:
  id: aboot
  title: Qualcomm aboot
  license: CC0-1.0
  ks-version: 0.9
  encoding: ASCII
  endian: le
doc: |
  A not so well documented format for aboot files, which can be found
  on some Android devices. This grammar only supports version 3 but not
  the `unified boot` version.

  Test file: hammerhead-krt16m-factory-fb4041cc.zip

  Version 2:

  * qsd8250_ffa
  * qsd8250_surf
  * qsd8650a_st1x

  Version 3:

  * apq8084
  * fsm9010
  * fsm9900
  * mdm9615
  * mdm9625
  * mdm9635
  * msm7627a
  * msm7627_surf
  * msm7630_surf
  * msm8226
  * msm8610
  * msm8660_surf
  * msm8960
  * msm8974

doc-ref: https://source.codeaurora.org/quic/la/kernel/lk/tree/target/msm8974/tools/mkheader.c?h=master&id=82117399ba17ea60b7f771c641ff5b1c9283bdc9#n161
seq:
  - id: appsbl
    type: u4
    valid: 5
  - id: version
    type: u4
    valid: 3
  - id: image_source_pointer
    type: u4
    valid: 0
  - id: image_destination_pointer
    type: u4
    # base
  - id: len_image
    type: u4
    # size + cert_chain_size + signature_size
  - id: len_code
    -orig-id: code_size
    type: u4
    # size
  - id: magic6
    type: u4
    # base + size
  - id: len_signature
    -orig-id: signature_size
    type: u4
  - id: magic8
    type: u4
    # size + base + signature_size
  - id: len_certificate_chain
    -orig-id: cert_chain_size
    type: u4
  - id: image
    size: len_image
    type: image
types:
  image:
    seq:
      - id: raw_appsbl
        size: _root.len_code
      - id: signature
        size: _root.len_signature
      - id: certificate_chain
        size: _root.len_certificate_chain
