rule zlib: license
{
    meta:
        description = "Rule for zlib license"
        name = "zlib"

    strings:

        $string1 = "www.zlib.net/zlib_license.html"

    condition:
        any of ($string*)

}
