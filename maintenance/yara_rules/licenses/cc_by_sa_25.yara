rule cc_by_sa_25: license
{
    meta:
        description = "Rule for CC-BY-SA-2.5 license"
        name = "cc_by_sa_20"

    strings:

        $string1 = "creativecommons.org/licenses/by-sa/2.5/"

    condition:
        any of ($string*)

}
