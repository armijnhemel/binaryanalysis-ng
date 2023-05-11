rule ietf: license
{
    meta:
        description = "Rule for IETF license"
        name = "ietf"

    strings:

        $string1 = "trustee.ietf.org/license-info/"

    condition:
        any of ($string*)

}
