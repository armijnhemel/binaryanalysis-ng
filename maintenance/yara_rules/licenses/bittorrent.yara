rule bittorrent: license
{
    meta:
        description = "Rule for BitTorrent license"
        name = "bittorrent"

    strings:

        $string1 = "www.bittorrent.com/license/"

    condition:
        any of ($string*)

}
