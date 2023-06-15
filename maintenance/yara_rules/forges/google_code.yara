rule google_code: forge
{
    meta:
        description = "Rule for Google Code references"
        name = "google_code"

    strings:

        $string1 = "code.google.com"
        $string2 = "googlecode.com"

    condition:
        any of ($string*)

}
