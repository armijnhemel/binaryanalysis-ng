rule gpl30_or_later: license
{
    meta:
        description = "Rule for GPL3.0-or-later"
        name = "gpl30_or_later"

    strings:

        $string1 = "License GPLv3+: GNU GPL version 3 or later"
        $string2 = "GPLv3+"

    condition:
        any of ($string*)

}
