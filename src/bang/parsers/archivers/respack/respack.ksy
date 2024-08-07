meta:
  id: respack
  title: ResPack
  license: CC0-1.0
  encoding: UTF-8
  endian: le
doc: |
  Resource file found in CPB firmware archives, mostly used on older CoolPad
  phones and/or tablets. The only observed files are called "ResPack.cfg".

  Also used as by Baidu Maps. Test files (file extension: .rs) can be found in:
  <https://www.asus.com/mobile-handhelds/wearable-healthcare/asus-vivowatch/asus-vivowatch-5-hc-b05/helpdesk_download/?model2Name=ASUS-VivoWatch-5-HC-B05>
seq:
  - id: header
    type: header
  - id: json
    size: header.len_json
    type: str
types:
  header:
    seq:
      - id: magic
        contents: "RS"
      - id: unknown
        size: 8
      - id: len_json
        type: u4
      - id: md5_bytes
        size: 32
        #type: str
        #encoding: ASCII
        doc: MD5 of data that follows the header
        valid:
          expr: '_.min >= 0x30 and _.max <= 0x66'
    instances:
      md5:
        value: md5_bytes.to_s('ascii')
