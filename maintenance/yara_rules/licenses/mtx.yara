rule mtx: license
{
    meta:
        description = "Rule for MTX license"
        name = "mtx"

    strings:

        $string1 = "www.monotype.com/legal/mtx-licensing-statement/"
        $string2 = "monotypeimaging.com/aboutus/mtx-license.aspx"

    condition:
        any of ($string*)

}
