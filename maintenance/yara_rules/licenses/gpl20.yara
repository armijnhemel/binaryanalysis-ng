rule gpl20: license copyleft
{
    meta:
        description = "Rule for GPL2.0"
        name = "gpl20"

    strings:

        $string1 = "gnu.org/licenses/gpl-2.0."
        $string2 = "gnu.org/licenses/old-licenses/gpl-2.0"
        $string3 = "creativecommons.org/licenses/GPL/2.0/"
        $string4 = "opensource.org/licenses/GPL-2.0"
        $string5 = "GPL v.2"
        $string6 = "GPL v2.0"

    condition:
        any of ($string*)

}
