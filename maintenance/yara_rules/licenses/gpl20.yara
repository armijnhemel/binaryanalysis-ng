rule gpl20: license
{
    meta:
        description = "Rule for GPL2.0"
        name = "gpl20"

    strings:

        // Extracted strings

        $string1 = "gnu.org/licenses/gpl-2.0."
        $string2 = "gnu.org/licenses/old-licenses/gpl-2.0"
        $string3 = "creativecommons.org/licenses/GPL/2.0/"
        $string4 = "opensource.org/licenses/GPL-2.0"

    condition:
        any of ($string*)

}
