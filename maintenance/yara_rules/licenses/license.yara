rule license: license
{
    meta:
        description = "Rule for generic license markers"
        name = "license"

    strings:

        $string1 = "license" nocase
        $string2 = "licence" nocase
        $string3 = "licensing"
        $string4 = "licencing"

    condition:
        any of ($string*)

}
