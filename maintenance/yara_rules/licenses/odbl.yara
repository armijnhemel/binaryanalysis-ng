rule odbl: license
{
    meta:
        description = "Rule for ODbl license"
        name = "odbl"

    strings:

        $string1 = "opendatacommons.org/licenses/odbl/"

    condition:
        any of ($string*)

}
