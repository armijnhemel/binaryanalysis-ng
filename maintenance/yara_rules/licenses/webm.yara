rule webm: license
{
    meta:
        description = "Rule for WebM license"
        name = "webm"

    strings:

        $string1 = "www.webmproject.org/license/software/"

    condition:
        any of ($string*)

}
