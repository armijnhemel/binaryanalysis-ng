rule yui: license
{
    meta:
        description = "Rule for Yui license"
        name = "yui"

    strings:

        $string1 = "developer.yahoo.com/yui/license.html"

    condition:
        any of ($string*)

}
