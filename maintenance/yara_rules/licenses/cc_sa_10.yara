rule cc_sa_10: license
{
    meta:
        description = "Rule for CC-SA-1.0 license"
        name = "cc_sa_10"

    strings:

        $string1 = "creativecommons.org/licenses/sa/1.0"

    condition:
        any of ($string*)

}
