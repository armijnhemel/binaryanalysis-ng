rule libreoffice: forge
{
    meta:
        description = "Rule for LibreOffice Git references"
        name = "libreoffice"

    strings:

        $string1 = "gerrit.libreoffice.org"

    condition:
        any of ($string*)

}
