rule cc_by_sa_40: license
{
    meta:
        description = "Rule for CC-BY-SA-4.0 license"
        name = "cc_by_sa_40"

    strings:

        $string1 = "creativecommons.org/licenses/by-sa/4.0/"

    condition:
        any of ($string*)

}
