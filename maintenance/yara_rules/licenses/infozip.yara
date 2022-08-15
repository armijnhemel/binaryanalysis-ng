rule infozip: license
{
    meta:
        description = "Rule for infozip license"
        name = "infozip"

    strings:

        $string1 = "www.info-zip.org/pub/infozip/license.html"

    condition:
        any of ($string*)

}
