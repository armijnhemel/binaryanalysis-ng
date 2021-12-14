rule gnu: license
{
    meta:
        description = "Rule for GNU references"
        name = "gnu"

    strings:

        $string1 = "gnu.org/licenses/"
        $string2 = "gnu.org/gethelp/"
        $string3 = "gnu.org/software/"
        $string4 = "@gnu.org"

    condition:
        any of ($string*)

}
