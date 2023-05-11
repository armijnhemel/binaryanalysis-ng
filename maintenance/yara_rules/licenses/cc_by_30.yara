rule cc_by_30: license
{
    meta:
        description = "Rule for CC-BY-3.0 license"
        name = "cc_by_30"

    strings:

        $string1 = "creativecommons.org/licenses/by/3.0/"

    condition:
        any of ($string*)

}
