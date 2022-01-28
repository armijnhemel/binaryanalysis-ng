rule ncurses: license
{
    meta:
        description = "Rule for ncurses license"
        name = "ncurses"

    strings:

        $string1 = "invisible-island.net/ncurses/ncurses-license.html"

    condition:
        any of ($string*)

}
