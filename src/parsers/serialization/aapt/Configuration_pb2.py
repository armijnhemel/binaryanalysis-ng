# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: Configuration.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13\x43onfiguration.proto\x12\x07\x61\x61pt.pb\"\xd9\x14\n\rConfiguration\x12\x0b\n\x03mcc\x18\x01 \x01(\r\x12\x0b\n\x03mnc\x18\x02 \x01(\r\x12\x0e\n\x06locale\x18\x03 \x01(\t\x12@\n\x10layout_direction\x18\x04 \x01(\x0e\x32&.aapt.pb.Configuration.LayoutDirection\x12\x14\n\x0cscreen_width\x18\x05 \x01(\r\x12\x15\n\rscreen_height\x18\x06 \x01(\r\x12\x17\n\x0fscreen_width_dp\x18\x07 \x01(\r\x12\x18\n\x10screen_height_dp\x18\x08 \x01(\r\x12 \n\x18smallest_screen_width_dp\x18\t \x01(\r\x12\x43\n\x12screen_layout_size\x18\n \x01(\x0e\x32\'.aapt.pb.Configuration.ScreenLayoutSize\x12\x43\n\x12screen_layout_long\x18\x0b \x01(\x0e\x32\'.aapt.pb.Configuration.ScreenLayoutLong\x12\x38\n\x0cscreen_round\x18\x0c \x01(\x0e\x32\".aapt.pb.Configuration.ScreenRound\x12?\n\x10wide_color_gamut\x18\r \x01(\x0e\x32%.aapt.pb.Configuration.WideColorGamut\x12\'\n\x03hdr\x18\x0e \x01(\x0e\x32\x1a.aapt.pb.Configuration.Hdr\x12\x37\n\x0borientation\x18\x0f \x01(\x0e\x32\".aapt.pb.Configuration.Orientation\x12\x37\n\x0cui_mode_type\x18\x10 \x01(\x0e\x32!.aapt.pb.Configuration.UiModeType\x12\x39\n\rui_mode_night\x18\x11 \x01(\x0e\x32\".aapt.pb.Configuration.UiModeNight\x12\x0f\n\x07\x64\x65nsity\x18\x12 \x01(\r\x12\x37\n\x0btouchscreen\x18\x13 \x01(\x0e\x32\".aapt.pb.Configuration.Touchscreen\x12\x36\n\x0bkeys_hidden\x18\x14 \x01(\x0e\x32!.aapt.pb.Configuration.KeysHidden\x12\x31\n\x08keyboard\x18\x15 \x01(\x0e\x32\x1f.aapt.pb.Configuration.Keyboard\x12\x34\n\nnav_hidden\x18\x16 \x01(\x0e\x32 .aapt.pb.Configuration.NavHidden\x12\x35\n\nnavigation\x18\x17 \x01(\x0e\x32!.aapt.pb.Configuration.Navigation\x12\x13\n\x0bsdk_version\x18\x18 \x01(\r\x12\x0f\n\x07product\x18\x19 \x01(\t\"a\n\x0fLayoutDirection\x12\x1a\n\x16LAYOUT_DIRECTION_UNSET\x10\x00\x12\x18\n\x14LAYOUT_DIRECTION_LTR\x10\x01\x12\x18\n\x14LAYOUT_DIRECTION_RTL\x10\x02\"\xaa\x01\n\x10ScreenLayoutSize\x12\x1c\n\x18SCREEN_LAYOUT_SIZE_UNSET\x10\x00\x12\x1c\n\x18SCREEN_LAYOUT_SIZE_SMALL\x10\x01\x12\x1d\n\x19SCREEN_LAYOUT_SIZE_NORMAL\x10\x02\x12\x1c\n\x18SCREEN_LAYOUT_SIZE_LARGE\x10\x03\x12\x1d\n\x19SCREEN_LAYOUT_SIZE_XLARGE\x10\x04\"m\n\x10ScreenLayoutLong\x12\x1c\n\x18SCREEN_LAYOUT_LONG_UNSET\x10\x00\x12\x1b\n\x17SCREEN_LAYOUT_LONG_LONG\x10\x01\x12\x1e\n\x1aSCREEN_LAYOUT_LONG_NOTLONG\x10\x02\"X\n\x0bScreenRound\x12\x16\n\x12SCREEN_ROUND_UNSET\x10\x00\x12\x16\n\x12SCREEN_ROUND_ROUND\x10\x01\x12\x19\n\x15SCREEN_ROUND_NOTROUND\x10\x02\"h\n\x0eWideColorGamut\x12\x1a\n\x16WIDE_COLOR_GAMUT_UNSET\x10\x00\x12\x1b\n\x17WIDE_COLOR_GAMUT_WIDECG\x10\x01\x12\x1d\n\x19WIDE_COLOR_GAMUT_NOWIDECG\x10\x02\"3\n\x03Hdr\x12\r\n\tHDR_UNSET\x10\x00\x12\x0e\n\nHDR_HIGHDR\x10\x01\x12\r\n\tHDR_LOWDR\x10\x02\"h\n\x0bOrientation\x12\x15\n\x11ORIENTATION_UNSET\x10\x00\x12\x14\n\x10ORIENTATION_PORT\x10\x01\x12\x14\n\x10ORIENTATION_LAND\x10\x02\x12\x16\n\x12ORIENTATION_SQUARE\x10\x03\"\xd7\x01\n\nUiModeType\x12\x16\n\x12UI_MODE_TYPE_UNSET\x10\x00\x12\x17\n\x13UI_MODE_TYPE_NORMAL\x10\x01\x12\x15\n\x11UI_MODE_TYPE_DESK\x10\x02\x12\x14\n\x10UI_MODE_TYPE_CAR\x10\x03\x12\x1b\n\x17UI_MODE_TYPE_TELEVISION\x10\x04\x12\x1a\n\x16UI_MODE_TYPE_APPLIANCE\x10\x05\x12\x16\n\x12UI_MODE_TYPE_WATCH\x10\x06\x12\x1a\n\x16UI_MODE_TYPE_VRHEADSET\x10\x07\"[\n\x0bUiModeNight\x12\x17\n\x13UI_MODE_NIGHT_UNSET\x10\x00\x12\x17\n\x13UI_MODE_NIGHT_NIGHT\x10\x01\x12\x1a\n\x16UI_MODE_NIGHT_NOTNIGHT\x10\x02\"m\n\x0bTouchscreen\x12\x15\n\x11TOUCHSCREEN_UNSET\x10\x00\x12\x17\n\x13TOUCHSCREEN_NOTOUCH\x10\x01\x12\x16\n\x12TOUCHSCREEN_STYLUS\x10\x02\x12\x16\n\x12TOUCHSCREEN_FINGER\x10\x03\"v\n\nKeysHidden\x12\x15\n\x11KEYS_HIDDEN_UNSET\x10\x00\x12\x1b\n\x17KEYS_HIDDEN_KEYSEXPOSED\x10\x01\x12\x1a\n\x16KEYS_HIDDEN_KEYSHIDDEN\x10\x02\x12\x18\n\x14KEYS_HIDDEN_KEYSSOFT\x10\x03\"`\n\x08Keyboard\x12\x12\n\x0eKEYBOARD_UNSET\x10\x00\x12\x13\n\x0fKEYBOARD_NOKEYS\x10\x01\x12\x13\n\x0fKEYBOARD_QWERTY\x10\x02\x12\x16\n\x12KEYBOARD_TWELVEKEY\x10\x03\"V\n\tNavHidden\x12\x14\n\x10NAV_HIDDEN_UNSET\x10\x00\x12\x19\n\x15NAV_HIDDEN_NAVEXPOSED\x10\x01\x12\x18\n\x14NAV_HIDDEN_NAVHIDDEN\x10\x02\"}\n\nNavigation\x12\x14\n\x10NAVIGATION_UNSET\x10\x00\x12\x14\n\x10NAVIGATION_NONAV\x10\x01\x12\x13\n\x0fNAVIGATION_DPAD\x10\x02\x12\x18\n\x14NAVIGATION_TRACKBALL\x10\x03\x12\x14\n\x10NAVIGATION_WHEEL\x10\x04\x42\x12\n\x10\x63om.android.aaptb\x06proto3')



_CONFIGURATION = DESCRIPTOR.message_types_by_name['Configuration']
_CONFIGURATION_LAYOUTDIRECTION = _CONFIGURATION.enum_types_by_name['LayoutDirection']
_CONFIGURATION_SCREENLAYOUTSIZE = _CONFIGURATION.enum_types_by_name['ScreenLayoutSize']
_CONFIGURATION_SCREENLAYOUTLONG = _CONFIGURATION.enum_types_by_name['ScreenLayoutLong']
_CONFIGURATION_SCREENROUND = _CONFIGURATION.enum_types_by_name['ScreenRound']
_CONFIGURATION_WIDECOLORGAMUT = _CONFIGURATION.enum_types_by_name['WideColorGamut']
_CONFIGURATION_HDR = _CONFIGURATION.enum_types_by_name['Hdr']
_CONFIGURATION_ORIENTATION = _CONFIGURATION.enum_types_by_name['Orientation']
_CONFIGURATION_UIMODETYPE = _CONFIGURATION.enum_types_by_name['UiModeType']
_CONFIGURATION_UIMODENIGHT = _CONFIGURATION.enum_types_by_name['UiModeNight']
_CONFIGURATION_TOUCHSCREEN = _CONFIGURATION.enum_types_by_name['Touchscreen']
_CONFIGURATION_KEYSHIDDEN = _CONFIGURATION.enum_types_by_name['KeysHidden']
_CONFIGURATION_KEYBOARD = _CONFIGURATION.enum_types_by_name['Keyboard']
_CONFIGURATION_NAVHIDDEN = _CONFIGURATION.enum_types_by_name['NavHidden']
_CONFIGURATION_NAVIGATION = _CONFIGURATION.enum_types_by_name['Navigation']
Configuration = _reflection.GeneratedProtocolMessageType('Configuration', (_message.Message,), {
  'DESCRIPTOR' : _CONFIGURATION,
  '__module__' : 'Configuration_pb2'
  # @@protoc_insertion_point(class_scope:aapt.pb.Configuration)
  })
_sym_db.RegisterMessage(Configuration)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\020com.android.aapt'
  _CONFIGURATION._serialized_start=33
  _CONFIGURATION._serialized_end=2682
  _CONFIGURATION_LAYOUTDIRECTION._serialized_start=1091
  _CONFIGURATION_LAYOUTDIRECTION._serialized_end=1188
  _CONFIGURATION_SCREENLAYOUTSIZE._serialized_start=1191
  _CONFIGURATION_SCREENLAYOUTSIZE._serialized_end=1361
  _CONFIGURATION_SCREENLAYOUTLONG._serialized_start=1363
  _CONFIGURATION_SCREENLAYOUTLONG._serialized_end=1472
  _CONFIGURATION_SCREENROUND._serialized_start=1474
  _CONFIGURATION_SCREENROUND._serialized_end=1562
  _CONFIGURATION_WIDECOLORGAMUT._serialized_start=1564
  _CONFIGURATION_WIDECOLORGAMUT._serialized_end=1668
  _CONFIGURATION_HDR._serialized_start=1670
  _CONFIGURATION_HDR._serialized_end=1721
  _CONFIGURATION_ORIENTATION._serialized_start=1723
  _CONFIGURATION_ORIENTATION._serialized_end=1827
  _CONFIGURATION_UIMODETYPE._serialized_start=1830
  _CONFIGURATION_UIMODETYPE._serialized_end=2045
  _CONFIGURATION_UIMODENIGHT._serialized_start=2047
  _CONFIGURATION_UIMODENIGHT._serialized_end=2138
  _CONFIGURATION_TOUCHSCREEN._serialized_start=2140
  _CONFIGURATION_TOUCHSCREEN._serialized_end=2249
  _CONFIGURATION_KEYSHIDDEN._serialized_start=2251
  _CONFIGURATION_KEYSHIDDEN._serialized_end=2369
  _CONFIGURATION_KEYBOARD._serialized_start=2371
  _CONFIGURATION_KEYBOARD._serialized_end=2467
  _CONFIGURATION_NAVHIDDEN._serialized_start=2469
  _CONFIGURATION_NAVHIDDEN._serialized_end=2555
  _CONFIGURATION_NAVIGATION._serialized_start=2557
  _CONFIGURATION_NAVIGATION._serialized_end=2682
# @@protoc_insertion_point(module_scope)