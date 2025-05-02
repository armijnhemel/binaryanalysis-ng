rule w3: license
{
    meta:
        description = "Rule for W3 license"
        name = "w3"

    strings:

        $string1 = "www.w3.org/Consortium/Legal/copyright-software-19980720"

    condition:
        any of ($string*)

}
