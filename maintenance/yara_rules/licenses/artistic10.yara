rule artistic10: license
{
    meta:
        description = "Rule for Artistic 1.0 license"
        name = "artistic10"

    strings:

        $string1 = "opensource.org/licenses/Artistic-1.0"
        $string2 = "opensource.org/licenses/Artistic-Perl-1.0"
        $string3 = "www.perlfoundation.org/artistic_license_1_0"

    condition:
        any of ($string*)

}
