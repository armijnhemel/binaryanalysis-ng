rule freebsd: license
{
    meta:
        description = "Rule for FreeBSD license"
        name = "freebsd"

    strings:

        $string1 = "www.freebsd.org/copyright/freebsd-license.html"

    condition:
        any of ($string*)

}
