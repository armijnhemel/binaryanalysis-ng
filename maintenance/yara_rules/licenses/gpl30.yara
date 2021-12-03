rule gpl30: license copyleft
{
    meta:
        description = "Rule for GPL3.0"
        name = "gpl30"

    strings:

        $string1 = "opensource.org/licenses/gpl-3.0."
        $string2 = "gnu.org/licenses/gpl-3.0."
        $string3 = "GPLv3" fullword

    condition:
        any of ($string*)

}
