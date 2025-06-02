meta:
  id: eot
  title: Embedded OpenType Font File
  file-extension: eot
  license: CC0-1.0
  endian: le
doc-ref:
  - https://www.w3.org/submissions/2008/SUBM-EOT-20080305/
seq:
  - id: header
    type: header
  - id: font_data
    size: header.len_data_size
    doc: |
      The font data for this EOT file. The data may be compressed or
      XOR encrypted as indicated by the processing flags.
types:
  header:
    seq:
      - id: len_eot
        type: u4
        doc: "Total structure length in bytes (including string and font data)"
      - id: len_data_size
        type: u4
        valid:
          min: 1
        doc: "Length of the OpenType font (FontData) in bytes"
      - id: version
        type: u4
        valid:
          any-of: [0x020001, 0x020002]
        doc: "Version number of this format - 0x00020001"
      - id: processing_flags
        type: u4
        doc: "Processing Flags"
      - id: font_panose
        size: 10
        doc: |
          The PANOSE value for this font
          See http://www.microsoft.com/typography/otspec/os2.htm#pan"
      - id: charset
        type: u1
        doc: |
          In Windows this is derived from TEXTMETRIC.tmCharSet. This value specifies the character
          set of the font. DEFAULT_CHARSET (0x01) indicates no preference.
          See http://msdn2.microsoft.com/en-us/library/ms534202.aspx"
      - id: italic
        type: u1
        doc: |
          If the bit for ITALIC is set in OS/2.fsSelection, the value will be 0x01
          See http://www.microsoft.com/typography/otspec/os2.htm#fss
      - id: weight
        type: u4
        doc: |
          The weight value for this font
          See http://www.microsoft.com/typography/otspec/os2.htm#wtc
      - id: fs_type
        type: u2
        doc: |
          Type flags that provide information about embedding permissions
          See http://www.microsoft.com/typography/otspec/os2.htm#fst
      - id: magic_number
        contents: [0x4c, 0x50]
        doc: "Magic number for EOT file - 0x504C. Used to check for data corruption."
      - id: unicode_range_1
        type: u4
        doc: "os/2.UnicodeRange1 (bits 0-31) - See http://www.microsoft.com/typography/otspec/os2.htm#ur"
      - id: unicode_range_2
        type: u4
        doc: "os/2.UnicodeRange2 (bits 32-63) - See http://www.microsoft.com/typography/otspec/os2.htm#ur"
      - id: unicode_range_3
        type: u4
        doc: "os/2.UnicodeRange3 (bits 64-95) - See http://www.microsoft.com/typography/otspec/os2.htm#ur"
      - id: unicode_range_4
        type: u4
        doc: "os/2.UnicodeRange4 (bits 96-127) - See http://www.microsoft.com/typography/otspec/os2.htm#ur"
      - id: codepage_range_1
        type: u4
        doc: "CodePageRange1 (bits 0-31) - See http://www.microsoft.com/typography/otspec/os2.htm#cpr"
      - id: codepage_range_2
        type: u4
        doc: "CodePageRange2 (bits 32-63) - See http://www.microsoft.com/typography/otspec/os2.htm#cpr"
      - id: checksum_adjustment
        type: u4
        doc: "head.CheckSumAdjustment - See http://www.microsoft.com/typography/otspec/head.htm"
      - id: reserved_1
        type: u4
        valid: 0
      - id: reserved_2
        type: u4
        valid: 0
      - id: reserved_3
        type: u4
        valid: 0
      - id: reserved_4
        type: u4
        valid: 0
      - id: padding_1
        type: u2
        valid: 0
        doc: "Padding to maintain long alignment. Padding value must always be set to 0x0000."
      - id: len_family_name
        type: u2
        doc: "Number of bytes used by the FamilyName array"
      - id: family_name
        size: len_family_name
        type: str
        encoding: utf-16
        doc: |
          Array of UTF-16 characters the length of FamilyNameSize bytes. This is the English language
          Font Family string found in the name table of the font (name ID = 1)
          See http://www.microsoft.com/typography/otspec/name.htm
      - id: padding_2
        type: u2
        valid: 0
      - id: len_style_name
        type: u2
        doc: "Number of bytes used by the StyleName"
      - id: style_name
        size: len_style_name
        type: str
        encoding: utf-16
        doc: |
          Array of UTF-16 characters the length of StyleNameSize bytes. This is the English language
          Font Subfamily string found in the name table of the font (name ID = 2)
          See http://www.microsoft.com/typography/otspec/name.htm
      - id: padding_3
        type: u2
        valid: 0
      - id: len_version_name
        type: u2
        doc: "Number of bytes used by the VersionName"
      - id: version_name
        size: len_version_name
        type: str
        encoding: utf-16
        doc: |
          Array of UTF-16 characters the length of VersionNameSize bytes. This is the English language
          version string found in the name table of the font (name ID = 5)
          See http://www.microsoft.com/typography/otspec/name.htm
      - id: padding_4
        type: u2
        valid: 0
      - id: len_full_name
        type: u2
      - id: full_name
        size: len_full_name
        type: str
        encoding: utf-16
        doc: |
          Array of UTF-16 characters the length of FullNameSize bytes. This is the English language
          full name string found in the name table of the font (name ID = 4)
          See http://www.microsoft.com/typography/otspec/name.htm"
      - id: padding_5
        type: u2
        valid: 0
      - id: len_root_string
        type: u2
      - id: root_string
        size: len_root_string
        type: str
        encoding: utf-16
        doc: "Array of UTF-16 characters the length of RootStringSize bytes."
      - id: version_header_22
        type: version_header_22
        if: version == 0x020002
  version_header_22:
    seq:
      - id: root_string_checksum
        type: u4
        doc: "RootString CheckSum value. See algorithm to process RootStringChecksum below."
      - id: eucd_code_page
        type: u4
        doc: "Codepage value needed for EUDC font support."
      - id: padding_6
        type: u2
        valid: 0
      - id: len_signature
        type: u2
      - id: signature
        size: len_signature
        doc: "Currently reserved. If the SignatureSize is 0x0000 there is no length to this array."
      - id: eucd_flags
        type: u4
        doc: |
          Processing flags for the EUDC font. Typical values might be
          TTEMBED_XORENCRYPTDATA and TTEMBED_TTCOMPRESSED.
      - id: len_eucd_font
        type: u4
        doc: "Number of bytes used by the Signature array."
      - id: eucd_font_data
        size: len_eucd_font
        doc: |
          Number of bytes used for the EUDC font data. If the EUDCFontSize
          is 0x00000000 there is no length to this array.
