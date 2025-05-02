rule tigris: forge
{
    meta:
        description = "Rule for Tigris.org SCM references"
        name = "tigris"

    strings:

        $string1 = "tigris.org"

    condition:
        any of ($string*)

}
