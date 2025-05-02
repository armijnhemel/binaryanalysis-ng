rule gpl30_or_later: license copyleft
{
    meta:
        description = "Rule for GPL-3.0-or-later"
        name = "gpl30_or_later"
        spdx_version = "3.15"
        spdx = " GPL-3.0-or-later"

    strings:

        $string1 = "License GPLv3+: GNU GPL version 3 or later"
        $string2 = "GPLv3+" fullword
        $string3 = "GPL version 3 or later" fullword

        $re1 = /License\sGPLv3\+:\sGNU\sGPL\sversion\s3\sor\slater/

    condition:
        any of ($string*) or any of ($re*)

}
