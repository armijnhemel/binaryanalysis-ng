rule cc_by_20: license
{
    meta:
        description = "Rule for CC-BY-2.0 license"
        name = "cc_by_20"

    strings:

        $string1 = "creativecommons.org/licenses/by/2.0/"

    condition:
        any of ($string*)

}
