rule sourceforge: forge
{
    meta:
        description = "Rule for SourceForge references"
        name = "sourceforge"

    strings:

        $string1 = "sourceforge.net"

    condition:
        any of ($string*)

}
