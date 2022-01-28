rule artistic20: license
{
    meta:
        description = "Rule for Artistic 2.0 license"
        name = "artistic20"

    strings:

        $string1 = "www.perlfoundation.org/artistic_license_2_0"
        $string2 = "opensource.org/licenses/artistic-license-2.0.php"

    condition:
        any of ($string*)

}
