rule artistic: license
{
    meta:
        description = "Rule for Artistic license"
        name = "artistic"

    strings:

        $string1 = "opensource.org/licenses/artistic-license.php"

    condition:
        any of ($string*)

}
