rule bsd: license
{
    meta:
        description = "Rule for BSD license"
        name = "bsd"

    strings:

        $string1 = "opensource.org/licenses/bsd-license"
        $string2 = "creativecommons.org/licenses/BSD/"

    condition:
        any of ($string*)

}
