rule cc_by_sa_30: license
{
    meta:
        description = "Rule for CC-BY-SA-3.0 license"
        name = "cc_by_sa_30"

    strings:

        $string1 = "creativecommons.org/licenses/by-sa/3.0/"

    condition:
        any of ($string*)

}
