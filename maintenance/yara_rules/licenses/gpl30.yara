rule gpl30: license
{
    meta:
        description = "Rule for GPL3.0"
        name = "gpl30"

    strings:

        $string1 = "opensource.org/licenses/gpl-3.0."
        $string2 = "gnu.org/licenses/gpl-3.0."

    condition:
        any of ($string*)

}
