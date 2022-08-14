rule gust: license
{
    meta:
        description = "Rule for GUST font license"
        name = "gust"

    strings:

        $string1 = "www.gust.org.pl/fonts/licenses/GUST-FONT-LICENSE.txt"

    condition:
        any of ($string*)

}
