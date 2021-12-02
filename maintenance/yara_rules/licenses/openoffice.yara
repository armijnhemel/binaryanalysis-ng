rule openoffice: license
{
    meta:
        description = "Rule for OpenOffice.org license"
        name = "openoffice"

    strings:

        $string1 = "www.openoffice.org/license.html"

    condition:
        any of ($string*)

}
