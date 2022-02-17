meta:
  id: pcapng
  title: pcapng
  license: CC0-1.0
  ks-version: 0.9
  encoding: utf-8
  endian: le
doc-ref: https://github.com/pcapng/pcapng
seq:
  - id: blocks
    type: block
    repeat: eos
types:
  block:
    seq:
      - id: header_type
        type: u4
        enum: header_types
        valid:
          any-of:
            - header_types::interface_description
            - header_types::packet_block
            - header_types::simple_packet
            - header_types::name_resolution
            - header_types::interface_statistics
            - header_types::enhanced_packet
            - header_types::decryption_secrets
            - header_types::custom
            - header_types::section_header
            - header_types::custom2
            - header_types::irig_timestamp
            - header_types::arinc_429
            - header_types::systemd_journal_expert
            - header_types::process_event
            - header_types::connection_event
            - header_types::sysdig_machine_info
            - header_types::sysdig_machine_info_version_1
            - header_types::sysdig_fd_list
            - header_types::sysdig_event
            - header_types::sysdig_interface_list
            - header_types::sysdig_user_list
            - header_types::sysdig_process_info_version_2
            - header_types::sysdig_event_with_flags
            - header_types::sysdig_process_info_version_3
            - header_types::sysdig_process_info_version_4
            - header_types::sysdig_process_info_version_5
            - header_types::sysdig_process_info_version_6
            - header_types::sysdig_process_info_version_7
      - id: len_block
        type: u4
      - id: rest_of_block
        type:
          switch-on: header_type
          cases:
            header_types::section_header: section_header_block
            header_types::interface_description: interface_description_block
            header_types::interface_statistics: interface_statistics_block
            header_types::enhanced_packet: enhanced_packet_block
            header_types::name_resolution: name_resolution_block
            header_types::decryption_secrets: decryption_secrets_block
        size: len_block - len_block._sizeof * 2 - header_type._sizeof
      - id: len_block2
        type: u4
        valid: len_block
  decryption_secrets_block:
    seq:
      - id: len_original_packet
        type: u4
  enhanced_packet_block:
    seq:
      - id: interface_id
        type: u4
      - id: timestamp
        type: timestamp
      - id: len_captured_packet
        type: u4
      - id: len_original_packet
        type: u4
      - id: data
        size: len_captured_packet
      - id: padding
        size: -len_captured_packet % 4
      - id: options
        type: option
        repeat: eos
  interface_description_block:
    seq:
      - id: linktype
        type: u2
        enum: linktype
      - id: reserved
        size: 2
      - id: snaplen
        type: u4
      - id: options
        type: option
        repeat: eos
  interface_statistics_block:
    seq:
      - id: interface_id
        type: u4
      - id: timestamp
        type: timestamp
      - id: options
        type: option
        repeat: eos
  section_header_block:
    seq:
      - id: byteorder_magic
        size: 4
      - id: version
        type: version
      - id: len_section
        type: s8
      - id: options
        type: option
        repeat: eos
  name_resolution_block:
    seq:
      - id: records
        type: record
        repeat: eos
      - id: options
        type: option
        repeat: eos
  record:
    seq:
      - id: type
        type: u2
        enum: name_records
        valid:
          any-of:
            - name_records::end
            - name_records::ipv4
            - name_records::ipv6
      - id: len_value
        type: u2
      - id: value
        size: len_value
      - id: padding
        size: -len_value % 4
    enums:
      name_records:
        0: end
        1: ipv4
        2: ipv6
  timestamp:
    seq:
      - id: high
        type: u4
      - id: low
        type: u4
  version:
    seq:
      - id: major
        type: u2
        valid: 1
      - id: minor
        type: u2
        valid: 0
  option:
    seq:
      - id: type
        type: u2
        enum: options
      - id: len_value
        type: u2
      - id: value
        size: len_value
      - id: padding
        size: -len_value % 4
    enums:
      options:
        0: end
        2988: custom1
        2989: custom2
        19372: custom3
        19373: custom4
enums:
  header_types:
    1: interface_description
    2: packet_block
    3: simple_packet
    4: name_resolution
    5: interface_statistics
    6: enhanced_packet
    0xa: decryption_secrets
    0x00000bad: custom
    0x0a0d0d0a: section_header
    0x40000bad: custom2

    # IRIG Timestamp Block
    7: irig_timestamp

    # ARINC 429
    8: arinc_429

    # https://datatracker.ietf.org/doc/html/draft-richardson-opsawg-pcapng-extras-00
    9: systemd_journal_expert

    # Linux sensor project
    # https://github.com/google/linux-sensor/blob/master/hone-pcapng.txt
    0x101: process_event
    0x102: connection_event

    # Sysdig
    #7: socket_aggregation_event
    0x201: sysdig_machine_info
    0x202: sysdig_machine_info_version_1
    0x203: sysdig_fd_list
    0x204: sysdig_event
    0x205: sysdig_interface_list
    0x206: sysdig_user_list
    0x207: sysdig_process_info_version_2
    0x208: sysdig_event_with_flags
    0x209: sysdig_process_info_version_3
    0x210: sysdig_process_info_version_4
    0x211: sysdig_process_info_version_5
    0x212: sysdig_process_info_version_6
    0x213: sysdig_process_info_version_7

  linktype:
    # https://www.tcpdump.org/linktypes.html
    0: null_linktype
    1: ethernet
    3: ax25
    6: ieee802_5
    7: arcnet_bsd
    8: slip
    9: ppp
    10: fddi
    50: ppp_hdlc
    51: ppp_ether
    100: atm_rfc1483
    101: raw
    104: c_hdlc
    105: ieee802_11
    107: frelay
    108: loop
    113: linux_sll
    114: ltalk
    117: pflog
    119: ieee802_11_prism
    122: ip_over_fc
    123: sunatm
    127: ieee802_11_radiotap
    129: arcnet_linux
    138: apple_ip_over_ieee1394
    139: mtp2_with_phdr
    140: mtp2
    141: mtp3
    142: sccp
    143: docsis
    144: linux_irda
    147: user0
    148: user1
    149: user2
    150: user3
    151: user4
    152: user5
    153: user6
    154: user7
    155: user8
    156: user9
    157: user10
    158: user11
    159: user12
    160: user13
    161: user14
    162: user15
    163: ieee802_11_avs
    165: bacnet_ms_tp
    166: ppp_pppd
    169: gprs_llc
    170: gpf_t
    171: gpf_f
    177: linux_lapd
    182: mfr
    187: bluetooth_hci_h4
    189: usb_linux
    192: ppi
    195: ieee802_15_4_withfcs
    196: sita
    197: erf
    201: bluetooth_hci_h4_with_phdr
    202: ax25_kiss
    203: lapd
    204: ppp_with_dir
    205: c_hdlc_with_dir
    206: frelay_with_dir
    207: lapb_with_dir
    209: ipmb_linux
    210: flexray
    212: lin
    215: ieee802_15_4_nonask_phy
    220: usb_linux_mmapped
    224: fc_2
    225: fc_2_with_frame_delims
    226: ipnet
    227: can_socketcan
    228: ipv4
    229: ipv6
    230: ieee802_15_4_nofcs
    231: dbus
    235: dvb_ci
    236: mux27010
    237: stanag_5066_d_pdu
    239: nflog
    240: netanalyzer
    241: netanalyzer_transparent
    242: ipoib
    243: mpeg_2_ts
    244: ng40
    245: nfc_llcp
    247: infiniband
    248: sctp
    249: usbpcap
    250: rtac_serial
    251: bluetooth_le_ll
    253: netlink
    254: bluetooth_linux_monitor
    255: bluetooth_bredr_bb
    256: bluetooth_le_ll_with_phdr
    257: profibus_dl
    258: pktap
    259: epon
    260: ipmi_hpm_2
    261: zwave_r1_r2
    262: zwave_r3
    263: wattstopper_dlm
    264: iso_14443
    265: rds
    266: usb_darwin
    268: sdlc
    270: loratap
    271: vsock
    272: nordic_ble
    273: docsis31_xra31
    274: ethernet_mpacket
    275: displayport_aux
    276: linux_sll2
    278: openvizsla
    279: ebhscr
    280: vpp_dispatch
    281: dsa_tag_brcm
    282: dsa_tag_brcm_prepend
    283: ieee802_15_4_tap
    284: dsa_tag_dsa
    285: dsa_tag_edsa
    286: elee
    287:
      id: zwave_serial
      -orig-id: LINKTYPE_Z_WAVE_SERIAL # `Z_WAVE` instead of `ZWAVE` is a name
                                       # inconsistency (other labels use `ZWAVE`)
    288: usb_2_0
    289: atsc_alp
    290: etw
    292: zboss_ncp
