rule gnu_savannah: forge
{
    meta:
        description = "Rule for GNU Savannah references"
        name = "gnu_savannah"

    strings:

        $string1 = "savannah.gnu.org"
        $string2 = "git.sv.gnu.org"

    condition:
        any of ($string*)

}
