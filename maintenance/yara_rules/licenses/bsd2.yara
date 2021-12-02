rule bsd2: license
{
    meta:
        description = "Rule for BSD-2-Clause license"
        name = "bsd2"

    strings:

        $string1 = "nmap.org/svn/docs/licenses/BSD-simplified"

    condition:
        any of ($string*)

}
