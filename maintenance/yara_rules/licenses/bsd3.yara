rule bsd3: license
{
    meta:
        description = "Rule for BSD-3-Clause license"
        name = "bsd3"

    strings:

        $string1 = "opensource.org/licenses/BSD-3-Clause"

    condition:
        any of ($string*)

}
