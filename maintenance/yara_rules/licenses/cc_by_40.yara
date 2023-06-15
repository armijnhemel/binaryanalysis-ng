rule cc_by_40: license
{
    meta:
        description = "Rule for CC-BY-4.0 license"
        name = "cc_by_40"

    strings:

        $string1 = "creativecommons.org/licenses/by/4.0/"

    condition:
        any of ($string*)

}
