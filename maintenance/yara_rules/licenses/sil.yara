rule sil: license
{
    meta:
        description = "Rule for SIL Open Font license"
        name = "sil"

    strings:

        $string1 = "scripts.sil.org/OFL"

    condition:
        any of ($string*)

}
