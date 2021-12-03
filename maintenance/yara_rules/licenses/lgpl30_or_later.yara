rule lgpl30_or_later: license copyleft
{
    meta:
        description = "Rule for LGPL3.0-or-later"
        name = "lgpl30_or_later"

    strings:

        $string1 = "LGPLv3+"

    condition:
        any of ($string*)

}
