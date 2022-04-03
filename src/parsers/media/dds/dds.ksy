meta:
  id: dds
  title: DirectDraw Surface
  file-extension: dds
  xref:
    mime: image/vnd-ms.dds
    pronom: fmt/1040
    wikidata: Q741654
  license: CC0-1.0
  ks-version: 0.9
  endian: le
seq:
  - id: magic
    -orig-id: dwMagic;
    contents: "DDS "
  - id: dds_header
    -orig-id: header
    type: dds_header
    doc-ref: https://docs.microsoft.com/en-us/windows/win32/direct3ddds/dds-header
  - id: dds_header_dxt10
    -orig-id: header10
    type: dds_header_dxt10
    if: dds_header.pixel_format.fourcc == "DX10"
types:
  dds_header:
    seq:
      - id: size
        -orig-id: dwSize
        type: u4
        valid: 124
      - id: flags
        -orig-id: dwFlags
        type: u4
      - id: height
        -orig-id: dwHeight
        type: u4
      - id: width
        -orig-id: dwWidth
        type: u4
      - id: pitch_or_linear_size
        -orig-id: dwPitchOrLinearSize
        type: u4
      - id: depth
        -orig-id: dwDepth
        type: u4
      - id: mip_map_count
        -orig-id: dwMipMapCount
        type: u4
      - id: reserved
        -orig-id: dwReserved1[11]
        size: 44
      - id: pixel_format
        -orig-id: ddspf
        type: pixel_format
      - id: caps
        -orig-id: dwCaps
        type: u4
      - id: caps2
        -orig-id: dwCaps2
        type: u4
      - id: caps3
        -orig-id: dwCaps3
        type: u4
      - id: caps4
        -orig-id: dwCaps4
        type: u4
      - id: reserved2
        -orig-id: dwReserved2
        contents: [0, 0, 0, 0]
  pixel_format:
    seq:
      - id: size
        -orig-id: dwSize
        type: u4
        valid: 32
      - id: flags
        -orig-id: dwFlags
        type: u4
      - id: fourcc
        -orig-id: dwFourCC
        type: str
        encoding: ASCII
        size: 4
      - id: rgb_bit_count
        -orig-id: dwRGBBitCount
        type: u4
      - id: red_bit_mask
        -orig-id: dwRBitMask
        type: u4
      - id: green_bit_mask
        -orig-id: dwGBitMask
        type: u4
      - id: blue_bit_mask
        -orig-id: dwBBitMask
        type: u4
      - id: alpha_bit_mask
        -orig-id: dwABitMask
        type: u4
  dds_header_dxt10:
    seq:
      - id: dxgi_format
        -orig-id: dxgiFormat
        type: u4
        enum: dxgi_formats
      - id: resource_dimension
        -orig-id: resourceDimension
        type: u4
        enum: d3d10_resource_dimensions
      - id: misc_flag
        -orig-id: miscFlag
        type: u4
      - id: array_size
        -orig-id: arraySize
        type: u4
      - id: misc_flags2
        -orig-id: miscFlags2
        type: u4
enums:
  dxgi_formats:
    0: dxgi_format_unknown
    1: dxgi_format_r32g32b32a32_typeless
    2: dxgi_format_r32g32b32a32_float
    3: dxgi_format_r32g32b32a32_uint
    5: dxgi_format_r32g32b32a32_sint
    6: dxgi_format_r32g32b32_typeless
    7: dxgi_format_r32g32b32_float
    8: dxgi_format_r32g32b32_uint
    9: dxgi_format_r32g32b32_sint
    10: dxgi_format_r16g16b16a16_typeless
    11: dxgi_format_r16g16b16a16_float
    12: dxgi_format_r16g16b16a16_unorm
    13: dxgi_format_r16g16b16a16_uint
    14: dxgi_format_r16g16b16a16_snorm
    15: dxgi_format_r16g16b16a16_sint
    16: dxgi_format_r32g32_typeless
    17: dxgi_format_r32g32_float
    18: dxgi_format_r32g32_uint
    19: dxgi_format_r32g32_sint
    20: dxgi_format_r32g8x24_typeless
    21: dxgi_format_d32_float_s8x24_uint
    22: dxgi_format_r32_float_x8x24_typeless
    23: dxgi_format_x32_typeless_g8x24_uint
    24: dxgi_format_r10g10b10a2_typeless
    25: dxgi_format_r10g10b10a2_unorm
    26: dxgi_format_r10g10b10a2_uint
    27: dxgi_format_r11g11b10_float
    28: dxgi_format_r8g8b8a8_typeless
    29: dxgi_format_r8g8b8a8_unorm
    30: dxgi_format_r8g8b8a8_unorm_srgb
    31: dxgi_format_r8g8b8a8_uint
    32: dxgi_format_r8g8b8a8_snorm
    33: dxgi_format_r8g8b8a8_sint
    34: dxgi_format_r16g16_typeless
    35: dxgi_format_r16g16_float
    36: dxgi_format_r16g16_unorm
    37: dxgi_format_r16g16_uint
    38: dxgi_format_r16g16_snorm
    39: dxgi_format_r16g16_sint
    40: dxgi_format_r32_typeless
    41: dxgi_format_d32_float
    42: dxgi_format_r32_float
    43: dxgi_format_r32_uint
    44: dxgi_format_r32_sint
    45: dxgi_format_r24g8_typeless
    46: dxgi_format_d24_unorm_s8_uint
    47: dxgi_format_r24_unorm_x8_typeless
    48: dxgi_format_x24_typeless_g8_uint
    49: dxgi_format_r8g8_typeless
    50: dxgi_format_r8g8_unorm
    51: dxgi_format_r8g8_uint
    52: dxgi_format_r8g8_snorm
    53: dxgi_format_r8g8_sint
    54: dxgi_format_r16_typeless
    55: dxgi_format_r16_float
    56: dxgi_format_d16_unorm
    57: dxgi_format_r16_unorm
    58: dxgi_format_r16_uint
    59: dxgi_format_r16_snorm
    60: dxgi_format_r16_sint
    61: dxgi_format_r8_typeless
    62: dxgi_format_r8_unorm
    63: dxgi_format_r8_uint
    64: dxgi_format_r8_snorm
    65: dxgi_format_r8_sint
    66: dxgi_format_a8_unorm
    67: dxgi_format_r1_unorm
    68: dxgi_format_r9g9b9e5_sharedexp
    69: dxgi_format_r8g8_b8g8_unorm
    70: dxgi_format_g8r8_g8b8_unorm
    71: dxgi_format_bc1_typeless
    72: dxgi_format_bc1_unorm
    73: dxgi_format_bc1_unorm_srgb
    74: dxgi_format_bc2_typeless
    75: dxgi_format_bc2_unorm
    76: dxgi_format_bc2_unorm_srgb
    77: dxgi_format_bc3_typeless
    78: dxgi_format_bc3_unorm
    79: dxgi_format_bc3_unorm_srgb
    80: dxgi_format_bc4_typeless
    81: dxgi_format_bc4_unorm
    82: dxgi_format_bc4_snorm
    83: dxgi_format_bc5_typeless
    84: dxgi_format_bc5_unorm
    85: dxgi_format_bc5_snorm
    86: dxgi_format_b5g6r5_unorm
    87: dxgi_format_b5g5r5a1_unorm
    88: dxgi_format_b8g8r8a8_unorm
    89: dxgi_format_b8g8r8x8_unorm
    90: dxgi_format_r10g10b10_xr_bias_a2_unorm
    91: dxgi_format_b8g8r8a8_typeless
    92: dxgi_format_b8g8r8a8_unorm_srgb
    93: dxgi_format_b8g8r8x8_typeless
    94: dxgi_format_b8g8r8x8_unorm_srgb
    95: dxgi_format_bc6h_typeless
    96: dxgi_format_bc6h_uf16
    97: dxgi_format_bc6h_sf16
    98: dxgi_format_bc7_typeless
    99: dxgi_format_bc7_unorm
    100: dxgi_format_bc7_unorm_srgb
    101: dxgi_format_ayuv
    102: dxgi_format_y410
    103: dxgi_format_y416
    104: dxgi_format_nv12
    105: dxgi_format_p010
    106: dxgi_format_p016
    107: dxgi_format_420_opaque
    108: dxgi_format_yuy2
    109: dxgi_format_y210
    110: dxgi_format_y216
    111: dxgi_format_nv11
    112: dxgi_format_ai44
    113: dxgi_format_ia44
    114: dxgi_format_p8
    115: dxgi_format_a8p8
    116: dxgi_format_b4g4r4a4_unorm
    117: dxgi_format_p208
    118: dxgi_format_v208
    119: dxgi_format_v408
    120: dxgi_format_sampler_feedback_min_mip_opaque
    121: dxgi_format_sampler_feedback_mip_region_used_opaque
    122: dxgi_format_force_uint
  d3d10_resource_dimensions:
    0: d3d10_resource_dimension_unknown
    1: d3d10_resource_dimension_buffer
    2: d3d10_resource_dimension_texture1d
    3: d3d10_resource_dimension_texture2d
    4: d3d10_resource_dimension_texture3d
