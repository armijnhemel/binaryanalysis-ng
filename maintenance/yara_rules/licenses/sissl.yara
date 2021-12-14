rule sissl: license
{
    meta:
        description = "Rule for SISSL"
        name = "sissl"

    strings:

        $string1 = "www.openoffice.org/licenses/sissl_license.html"

    condition:
        any of ($string*)

}
