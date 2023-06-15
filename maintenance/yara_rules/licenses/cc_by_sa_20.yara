rule cc_by_sa_20: license
{
    meta:
        description = "Rule for CC-BY-SA-2.0 license"
        name = "cc_by_sa_20"

    strings:

        $string1 = "creativecommons.org/licenses/by-sa/2.0/"

    condition:
        any of ($string*)

}
