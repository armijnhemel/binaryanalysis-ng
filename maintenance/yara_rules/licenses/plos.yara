rule plos: license
{
    meta:
        description = "Rule for PLOS license"
        name = "plos"

    strings:

        $string1 = "www.ploscompbiol.org/static/license"

    condition:
        any of ($string*)

}
