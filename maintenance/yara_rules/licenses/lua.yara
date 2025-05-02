rule lua: license
{
    meta:
        description = "Rule for Lua license"
        name = "lua"

    strings:

        $string1 = "www.lua.org/license.html"

    condition:
        any of ($string*)

}
