rule license: license
{
    meta:
        description = "Rule for generic license markers"
        name = "license"

    strings:

        // Extracted strings

        $string1 = "license"
        $string2 = "License"
        $string3 = "LICENSE"
        $string4 = "licensing"
        $string5 = "licence"
        $string6 = "Licence"
        $string7 = "LICENCE"
        $string8 = "licencing"

    condition:
        any of ($string*)

}
